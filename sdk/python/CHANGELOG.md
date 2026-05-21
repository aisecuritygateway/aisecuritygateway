# Changelog

## 0.1.0 (2026-05-21)

Initial release.

- `AISG` sync client and `AsyncAISG` async client
- `client.chat.create()` — chat completions with typed `AISGMetadata`
- `client.models.list()` — model discovery with filtering
- Streaming support via `stream=True`
- Typed exceptions: `DLPBlockError`, `BudgetExhaustedError`, `RateLimitError`, `ModelNotFoundError`
- Works with managed cloud and self-hosted deployments
- Environment variable configuration (`AISG_API_KEY`, `AISG_BASE_URL`)
