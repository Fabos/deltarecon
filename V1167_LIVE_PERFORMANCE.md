# v0.116.7 · LIVE Performance

This patch keeps v0.116.6 live detail hydration but removes the latency and DOM growth that could make HTTP Workbench feel progressively heavy.

- Detail clicks cancel the previous in-flight request.
- The normal click path performs one immediate fetch; only a real 404 gets one 85 ms retry.
- Older detail responses can no longer overwrite a newer selection.
- The clicked row becomes active immediately for perceived responsiveness.
- Traffic Inbox keeps a bounded live DOM window (650 rows) while the persisted history remains untouched and available through filters/history/checkpoints.
- LIVE polling never overlaps with itself and slows down while the browser tab is hidden.
