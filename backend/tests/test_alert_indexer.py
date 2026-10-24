"""Tests for Task 5: Event Search and OpenSearch Indexer Resilience."""

from __future__ import annotations

import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from app import app, alerts
import app as app_module
from storage.alert_indexer import (
    SqlAlertIndexer,
    OpenSearchIndexer,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class FailingThenRecoveringClient:
    """Fake OpenSearch client that fails N times before recovering."""

    def __init__(self, failures_before_success: int = 2) -> None:
        self.failures_before_success = failures_before_success
        self.attempts = 0
        self.indexed_docs: List[Dict[str, Any]] = []

    def index(self, index: str, id: str, body: Dict[str, Any]) -> None:
        self.attempts += 1
        if self.attempts <= self.failures_before_success:
            raise ConnectionError(f"OpenSearch unreachable (attempt {self.attempts})")
        self.indexed_docs.append(body)


class BrokenOpenSearchClient:
    """Fake OpenSearch client that is permanently down."""

    def __init__(self) -> None:
        self.attempts = 0

    def index(self, index: str, id: str, body: Dict[str, Any]) -> None:
        self.attempts += 1
        raise ConnectionError("Cluster connection refused: 9200")


def test_sql_default_behavior_and_501_when_disabled(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """SQL default indexer is disabled for external search and GET /api/search/alerts returns 501."""
    monkeypatch.setattr(app_module, "global_alert_indexer", SqlAlertIndexer())

    # Alert creation must work cleanly with SQL default
    alert_rec = alerts.add(
        source="unit_test",
        severity="low",
        category="Policy",
        message="Standard SQL alert creation",
        meta={},
    )
    assert alert_rec.id is not None

    # Search endpoint must return HTTP 501 Not Implemented
    resp = client.get("/api/search/alerts?q=ransomware")
    assert resp.status_code == 501
    assert "disabled" in resp.json()["detail"].lower()


def test_indexer_queue_retries_with_backoff_when_down() -> None:
    """When OpenSearch is temporarily down, the worker retries with backoff and eventually succeeds."""
    fake_client = FailingThenRecoveringClient(failures_before_success=2)
    indexer = OpenSearchIndexer(
        client=fake_client,
        initial_backoff=0.05,
        max_backoff=0.2,
    )

    alert_payload = {
        "id": 999,
        "category": "DDoS",
        "severity": "critical",
        "message": "Syn flood detected",
    }

    start_time = time.monotonic()
    # Call index_alert: must return immediately without blocking
    indexer.index_alert(alert_payload)
    elapsed = time.monotonic() - start_time
    assert elapsed < 0.1  # Completely non-blocking

    # Wait for the worker thread to retry with backoff and succeed
    timeout = 3.0
    while len(fake_client.indexed_docs) == 0 and time.monotonic() - start_time < timeout:
        time.sleep(0.05)

    assert fake_client.attempts >= 3
    assert len(fake_client.indexed_docs) == 1
    assert fake_client.indexed_docs[0]["category"] == "DDoS"
    indexer.close()


def test_indexer_queue_overflow_drops_without_blocking_alert_creation() -> None:
    """When OpenSearch is permanently down and the queue fills up, alerts are dropped without blocking."""
    broken_client = BrokenOpenSearchClient()
    # Tiny queue to test overflow quickly
    indexer = OpenSearchIndexer(
        client=broken_client,
        queue_maxsize=3,
        initial_backoff=0.5,
        max_backoff=1.0,
    )

    # Push 10 alerts rapidly
    t0 = time.monotonic()
    for i in range(10):
        indexer.index_alert({"id": i, "message": f"Alert {i}"})
    total_time = time.monotonic() - t0

    # Must complete almost instantly despite the broken client
    assert total_time < 0.2
    assert indexer._dropped_count > 0
    indexer.close()


def test_opensearch_search_when_enabled(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """When OpenSearch is enabled, GET /api/search/alerts returns hits from indexer."""
    class SearchableMockClient:
        def search(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
            q = body.get("query", {}).get("query_string", {}).get("query", "")
            return {
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_id": "alert-42",
                            "_source": {
                                "id": 42,
                                "category": "Phishing",
                                "severity": "high",
                                "query_matched": q,
                            },
                        }
                    ],
                }
            }

    mock_client = SearchableMockClient()
    enabled_indexer = OpenSearchIndexer(client=mock_client)
    monkeypatch.setattr(app_module, "global_alert_indexer", enabled_indexer)

    resp = client.get("/api/search/alerts?q=malicious.domain")
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == "malicious.domain"
    assert data["count"] == 1
    assert data["results"][0]["category"] == "Phishing"
    enabled_indexer.close()
