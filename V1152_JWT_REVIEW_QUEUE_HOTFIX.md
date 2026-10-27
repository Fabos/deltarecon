# Negro v0.115.2 · JWT + Review Queue Hotfix

- JWT is rendered as a real inline button and opens the JWT Inspector through an independent capture-phase handler.
- JWT Inspector keeps the full token, decoded Header/Claims, human-readable time claims and signature warning.
- The bottom live indicator is now a session-local **review queue**, not a raw arrival counter.
- Every live unread event enters the review queue; opening that event removes it immediately without reload.
- The bottom action moves to the next pending event; `Seguir LIVE` remains a separate explicit action.
- Global unread state and the local live review queue remain separate concepts.
