# Action2MCP 0.6.2

- Fixes the v0.6.1 filename regression: application startup again opens the original `data/a2m.db`, not the accidentally renamed `a2m.DB()`. The original data was not deleted; the wrong filename opened a separate empty database.
- Includes the feature-package refactor. No new features, database migration or approval-policy changes; schema remains 12.
- Preserve the entire existing `data` directory, `secret.key` and config. Any shadow `a2m.DB()` is left untouched: no automatic deletion or merge of possible records.
- Regression coverage includes independent existing-data fixtures, actual opened filename, HTTP/MCP catalog visibility, existing shadow preservation and repository empty/error contracts. Full corrective tests/race/vet passed; release checks include four-platform builds and isolated Linux smoke, HTTP/stdio/official MCP SDK and baseline-created legacy-data upgrade acceptance.
- Cross-builds do not certify every native platform, browser/SSO or real database/MQ integration. v0.6.1 remains warned and its assets/tag are unchanged.
