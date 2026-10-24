"""Alert Indexer Interface and OpenSearch Full-Text Search Backend."""

from __future__ import annotations

import abc
import logging
import os
import queue
import threading
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("volcano.alert_indexer")


class AlertIndexer(abc.ABC):
    """Abstract interface for indexing security alerts and performing full-text search."""

    @abc.abstractmethod
    def index_alert(self, alert: Dict[str, Any]) -> None:
        """Queue or index an alert record. Must never block the caller."""
        raise NotImplementedError

    @abc.abstractmethod
    def search(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Perform search query across indexed alerts."""
        raise NotImplementedError

    @abc.abstractmethod
    def is_enabled(self) -> bool:
        """Return True if full-text search indexer is active."""
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        """Gracefully shut down workers and flush queues."""
        raise NotImplementedError


class SqlAlertIndexer(AlertIndexer):
    """
    Default AlertIndexer using the primary SQL database.
    Does not run an external search engine.
    """

    def index_alert(self, alert: Dict[str, Any]) -> None:
        # Synchronous SQL persistence is handled directly by Database.save_alert()
        pass

    def search(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        raise NotImplementedError(
            "Full-text alert search requires OpenSearch backend (VOLCANO_SEARCH_BACKEND=opensearch)."
        )

    def is_enabled(self) -> bool:
        return False

    def close(self) -> None:
        pass


class OpenSearchIndexer(AlertIndexer):
    """
    Asynchronous OpenSearch Alert Indexer with bounded queue and exponential backoff retry.
    Guarantees that indexer outages or latency never block alert creation in the core engine.
    """

    def __init__(
        self,
        opensearch_url: str = "http://localhost:9200",
        index_name: str = "volcano-alerts",
        queue_maxsize: int = 2000,
        client: Optional[Any] = None,
        initial_backoff: float = 0.5,
        max_backoff: float = 8.0,
    ) -> None:
        self.opensearch_url = opensearch_url.rstrip("/")
        self.index_name = index_name
        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=queue_maxsize)
        self.client = client
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self._running = True
        self._failed_attempts = 0
        self._indexed_count = 0
        self._dropped_count = 0

        self._worker_thread = threading.Thread(target=self._index_worker, daemon=True)
        self._worker_thread.start()

    def is_enabled(self) -> bool:
        return True

    def index_alert(self, alert: Dict[str, Any]) -> None:
        """
        Put alert into queue non-blocking.
        If queue is full, drop the alert to maintain zero latency impact on packet pipeline.
        """
        try:
            self.queue.put_nowait(alert)
        except queue.Full:
            self._dropped_count += 1
            logger.warning(
                "OpenSearch indexer queue full (size=%d). Dropping alert indexing to avoid blocking core pipeline.",
                self.queue.maxsize,
            )

    def _index_worker(self) -> None:
        backoff = self.initial_backoff
        while self._running:
            try:
                alert = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue

            success = False
            while self._running and not success:
                try:
                    self._perform_index(alert)
                    success = True
                    self._indexed_count += 1
                    backoff = self.initial_backoff
                    self._failed_attempts = 0
                except Exception as exc:
                    self._failed_attempts += 1
                    logger.warning(
                        "OpenSearch index failure (attempt %d, backoff=%.1fs): %s",
                        self._failed_attempts,
                        backoff,
                        exc,
                    )
                    time.sleep(backoff)
                    backoff = min(self.max_backoff, backoff * 2)

            self.queue.task_done()

    def _perform_index(self, alert: Dict[str, Any]) -> None:
        alert_id = str(alert.get("id") or alert.get("timestamp") or time.time())
        if self.client is not None:
            # Custom or mocked test client
            if hasattr(self.client, "index"):
                self.client.index(index=self.index_name, id=alert_id, body=alert)
            elif hasattr(self.client, "post"):
                resp = self.client.post(
                    f"{self.opensearch_url}/{self.index_name}/_doc/{alert_id}",
                    json=alert,
                    timeout=5,
                )
                if getattr(resp, "status_code", 200) >= 400:
                    raise RuntimeError(f"OpenSearch error HTTP {resp.status_code}: {resp.text}")
            return

        # Direct HTTP via requests
        url = f"{self.opensearch_url}/{self.index_name}/_doc/{alert_id}"
        resp = requests.post(url, json=alert, timeout=5)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"OpenSearch index failed with status {resp.status_code}: {resp.text}")

    def search(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Perform search query against OpenSearch."""
        if self.client is not None:
            if hasattr(self.client, "search"):
                res = self.client.search(
                    index=self.index_name,
                    body={"query": {"query_string": {"query": query}}, "size": limit},
                )
                hits = res.get("hits", {}).get("hits", [])
                return [h.get("_source", {}) for h in hits]
            elif hasattr(self.client, "get"):
                resp = self.client.get(
                    f"{self.opensearch_url}/{self.index_name}/_search",
                    params={"q": query, "size": limit},
                    timeout=5,
                )
                data = resp.json()
                return [h.get("_source", {}) for h in data.get("hits", {}).get("hits", [])]

        url = f"{self.opensearch_url}/{self.index_name}/_search"
        resp = requests.get(url, params={"q": query, "size": limit}, timeout=5)
        if resp.status_code >= 400:
            raise RuntimeError(f"OpenSearch query failed: {resp.status_code} {resp.text}")
        data = resp.json()
        return [h.get("_source", {}) for h in data.get("hits", {}).get("hits", [])]

    def close(self) -> None:
        self._running = False


def get_alert_indexer(
    backend: Optional[str] = None,
    opensearch_url: Optional[str] = None,
    opensearch_index: Optional[str] = None,
    client: Optional[Any] = None,
) -> AlertIndexer:
    """Factory creating the configured AlertIndexer."""
    chosen_backend = (backend or os.getenv("VOLCANO_SEARCH_BACKEND", "sql")).lower().strip()
    if chosen_backend == "opensearch":
        url = opensearch_url or os.getenv("VOLCANO_OPENSEARCH_URL", "http://localhost:9200")
        idx = opensearch_index or os.getenv("VOLCANO_OPENSEARCH_INDEX", "volcano-alerts")
        return OpenSearchIndexer(opensearch_url=url, index_name=idx, client=client)
    return SqlAlertIndexer()
