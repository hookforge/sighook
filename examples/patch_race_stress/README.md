# patch_race_stress

Stress-validates runtime patch synchronization by repeatedly hook/unhooking a
function entry from a background thread while multiple worker threads call the
target function in a tight loop.

Expected output with the payload loaded:

```text
stress ok
```
