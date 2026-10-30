# v0.116.9 — Styled First Frame

Workbench no longer paints raw/plain HTTP and then restyles it when full context arrives.

- Fast previews use the same HTTP syntax palette and line-number layout as the hydrated inspector.
- Pretty JSON is applied in the preview path too.
- JWT/long-value compaction that can be determined locally is available on the first frame.
- Full detail only enriches the already-styled HTTP with semantic interaction/context.
- If a preview is genuinely unavailable, Request/Response show a low-glare skeleton instead of stale/plain content.
- A late preview can no longer overwrite an already hydrated rich detail render.
