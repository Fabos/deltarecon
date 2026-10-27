# Negro v0.113 · Semantic HTTP Workbench

Second Workbench polish pass focused on long analysis sessions.

- Pretty is now the default for Request and Response.
- HTTP code density reduced from 1.6 to 1.4 line-height.
- Workbench reuses `learned_annotations()` from the existing HTTP Inspector.
- Learned AUTH, RESOLVER, CONTEXT and ENTITY evidence is highlighted inline.
- Identity names are displayed with the HTTP evidence that recognized them.
- A compact semantic summary appears beside the selected request metadata.
- Existing Identity assignment remains authoritative; inferred HTTP matches are shown as recognized evidence rather than silently becoming manual assignments.
