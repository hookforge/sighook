# prepatched_upgrade_execute_original

Validates the prepatched workflow where a slot is first registered with
`prepatched::instrument_no_original(...)` and later upgraded to
`prepatched::instrument(...)` after caching the real original opcode.

Expected output with the payload loaded:

```text
calc_prepatched() = 42
```
