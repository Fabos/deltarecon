# v0.116.8 — Instant HTTP Navigation

The HTTP Workbench now separates two latency classes:

1. **Immediate HTTP preview** — raw Request/Response, method, URL, status and size.
2. **Asynchronous semantic hydration** — Identity, Objects, Signals, Flow, Related, JWT annotations and Actions.

The browser keeps a bounded preview cache and preloads neighboring events. LIVE poll responses attach previews for the newest events. This makes click/Arrow navigation feel local while preserving the richer Negro context when it finishes loading.
