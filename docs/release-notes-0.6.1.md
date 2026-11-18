# Action2MCP 0.6.1

- Includes the feature-package refactor from `09e4336`: App is now lifecycle/composition only; recording analysis, middleware tools, approval invocation, repositories, console and MCP adapters have explicit owners and ports.
- Preserves CLI/HTTP/MCP contracts, approval and credential policy, saved-data paths and schema user_version 12. No new features or migrations. Keep the existing `data` directory and `secret.key` when upgrading.
- Release validation: Go tests and vet; four-target cross-builds; isolated Linux executable smoke and HTTP/stdio/official MCP SDK acceptance.
- Cross-build success is not native-platform certification. Windows/macOS execution, real browser/SSO and real database/MQ integrations are not covered by the isolated Linux release acceptance.
