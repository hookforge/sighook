# instrument_blr_lr

Validates that execute-original on an AArch64 `blr` patchpoint preserves architectural `lr`.

Expected output with the payload loaded:

```text
observe_lr() = 0x... expected = 0x...
```

The two addresses must match.
