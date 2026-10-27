# Negro v0.115.5 — Burp-style Traffic Deck

This iteration changes the HTTP Workbench information hierarchy without changing capture semantics.

## Layout

- Traffic Inbox is a full-width top deck.
- HTTP Request/Response is the primary analysis surface below it.
- Context stays on the right of the analysis surface and can be collapsed independently.

## Traffic modes

### Expanded
A dense Burp-like table shows:
- capture event sequence;
- method;
- host;
- endpoint + compact request parameters;
- context tags;
- status;
- timestamp.

### Collapsed
Press `T` (or the Traffic controls) to collapse the deck. Negro keeps a compact orientation bar with the selected method, host/path, status, Event # and unread count. Request/Response immediately gains the released height.

## Keyboard

- `T`: collapse/expand Traffic Inbox.
- `C`: collapse/expand Context.
- `F`: Focus Mode.
- `J/K` or arrow keys: previous/next request.

The collapsed state is persisted locally per browser.
