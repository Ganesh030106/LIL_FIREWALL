## Description
<!-- Provide a brief summary of the changes introduced by this pull request. -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature that alters existing behavior)
- [ ] Documentation update
- [ ] CI / Tooling improvement

## Pre-Merge Verification Checklist
Please confirm that your changes meet the following criteria before requesting review:

- [ ] **Tests Added / Updated**: Unit and integration tests covering new or modified behavior have been added and pass locally.
- [ ] **Docs Updated**: All relevant documentation files in `docs/` and `CHANGELOG.md` reflect the changes (including API schemas, parameters, and test counts).
- [ ] **Database Migration Included**: If database schemas or column models were modified, an accompanying Alembic migration is included in `backend/alembic/versions/`.
- [ ] **No Secrets in Diff**: Verified that no API keys, private credentials, or secrets (e.g. `VOLCANO_JWT_SECRET_KEY`) appear in commit diffs or configuration examples.
- [ ] **Lint & Typechecks Pass**: `ruff check backend` and `mypy backend` run without introducing new regressions.
