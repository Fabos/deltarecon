from __future__ import annotations

import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any

import negro_parameters as parameter_tools


STATE_HINTS = (
    "status", "state", "phase", "stage", "step", "paymentstatus", "payment_status",
    "orderstatus", "order_status", "shipmentstatus", "shipment_status", "deliverystatus", "delivery_status",
)
BUSINESS_VALUE_HINTS = (
    "id", "owner", "user", "account", "tenant", "seller", "buyer", "customer", "order", "invoice",
    "payment", "shipment", "price", "amount", "total", "discount", "coupon", "quantity", "status", "state",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            identity_id INTEGER,
            context_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS flow_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            exchange_id INTEGER NOT NULL,
            label TEXT,
            state_label TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(flow_id, exchange_id),
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_flow_steps_flow ON flow_steps(flow_id, position);
        CREATE INDEX IF NOT EXISTS idx_flow_steps_exchange ON flow_steps(exchange_id);
        """
    )


def _normalize_path(path: str) -> str:
    parts = []
    for seg in str(path or "").split("/"):
        if not seg:
            continue
        if re.fullmatch(r"\d{2,}", seg) or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", seg) or (len(seg) >= 8 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg)):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def _signature(step: dict[str, Any]) -> str:
    return f"{str(step.get('method') or '').upper()} {_normalize_path(str(step.get('path') or ''))}"


def create_flow(conn, name: str, *, description: str = "", identity_id: int | None = None, context_id: int | None = None) -> int:
    init_schema(conn)
    name = str(name or "").strip()[:160]
    if not name:
        raise ValueError("Nombre del flow requerido")
    now = now_iso()
    cur = conn.execute(
        "INSERT INTO flows(name,description,identity_id,context_id,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        (name, str(description or "")[:4000], identity_id, context_id, now, now),
    )
    return int(cur.lastrowid)


def list_flows(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    rows = conn.execute(
        """SELECT f.*,i.name identity_name,c.label context_label,
                  COUNT(fs.id) step_count,MIN(fs.exchange_id) first_exchange,MAX(fs.exchange_id) last_exchange
           FROM flows f
           LEFT JOIN identities i ON i.id=f.identity_id
           LEFT JOIN identity_contexts c ON c.id=f.context_id
           LEFT JOIN flow_steps fs ON fs.flow_id=f.id
           GROUP BY f.id ORDER BY f.updated_at DESC,f.id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def add_step(conn, flow_id: int, exchange_id: int, *, label: str = "", state_label: str = "", notes: str = "") -> int:
    init_schema(conn)
    if not conn.execute("SELECT id FROM flows WHERE id=?", (int(flow_id),)).fetchone():
        raise ValueError("Flow no encontrado")
    if not conn.execute("SELECT id FROM http_exchanges WHERE id=?", (int(exchange_id),)).fetchone():
        raise ValueError("Exchange no encontrado")
    existing = conn.execute("SELECT id FROM flow_steps WHERE flow_id=? AND exchange_id=?", (int(flow_id), int(exchange_id))).fetchone()
    if existing:
        return int(existing["id"])
    pos = int(conn.execute("SELECT COALESCE(MAX(position),0)+1 n FROM flow_steps WHERE flow_id=?", (int(flow_id),)).fetchone()["n"])
    now = now_iso()
    cur = conn.execute(
        "INSERT INTO flow_steps(flow_id,position,exchange_id,label,state_label,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (int(flow_id), pos, int(exchange_id), str(label or "")[:200], str(state_label or "")[:160], str(notes or "")[:3000], now, now),
    )
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))
    return int(cur.lastrowid)


def add_range(conn, flow_id: int, start_exchange: int, end_exchange: int, *, exclude_options: bool = True) -> dict[str, int]:
    init_schema(conn)
    lo, hi = sorted((int(start_exchange), int(end_exchange)))
    sql = """SELECT e.id,o.method FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
             WHERE e.id BETWEEN ? AND ? ORDER BY e.id"""
    rows = conn.execute(sql, (lo, hi)).fetchall()
    added = 0
    skipped = 0
    for row in rows:
        if exclude_options and str(row["method"]).upper() == "OPTIONS":
            skipped += 1
            continue
        before = conn.execute("SELECT id FROM flow_steps WHERE flow_id=? AND exchange_id=?", (int(flow_id), int(row["id"]))).fetchone()
        add_step(conn, int(flow_id), int(row["id"]))
        if before:
            skipped += 1
        else:
            added += 1
    return {"added": added, "skipped": skipped}


def remove_step(conn, flow_id: int, step_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM flow_steps WHERE id=? AND flow_id=?", (int(step_id), int(flow_id)))
    rows = conn.execute("SELECT id FROM flow_steps WHERE flow_id=? ORDER BY position,id", (int(flow_id),)).fetchall()
    for idx, row in enumerate(rows, 1):
        conn.execute("UPDATE flow_steps SET position=? WHERE id=?", (idx, int(row["id"])))
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now_iso(), int(flow_id)))


def update_step(conn, flow_id: int, step_id: int, *, label: str = "", state_label: str = "", notes: str = "") -> None:
    init_schema(conn)
    now = now_iso()
    conn.execute(
        "UPDATE flow_steps SET label=?,state_label=?,notes=?,updated_at=? WHERE id=? AND flow_id=?",
        (str(label or "")[:200], str(state_label or "")[:160], str(notes or "")[:3000], now, int(step_id), int(flow_id)),
    )
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))


def _business_observations(conn, exchange_id: int, *, limit: int = 20) -> list[dict[str, Any]]:
    rows = [dict(r) for r in conn.execute(
        """SELECT p.id,p.name,p.normalized_name,p.location,COALESCE(p.value_raw,p.value_preview) value
           FROM parameter_observations p WHERE p.exchange_id=? ORDER BY p.id""", (int(exchange_id),)
    ).fetchall()]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        name = str(row.get("normalized_name") or "").lower()
        if not any(h in name for h in BUSINESS_VALUE_HINTS):
            continue
        value = str(row.get("value") or "")
        key = (name, value)
        if key in seen:
            continue
        seen.add(key)
        row["is_state"] = any(h == name or h in name for h in STATE_HINTS)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def _step_row(conn, step_row) -> dict[str, Any]:
    row = conn.execute(
        """SELECT fs.*,e.status_code,e.first_seen_at,o.method,o.resource_id,r.path,h.hostname,
                  ei.identity_id,i.name identity_name,ic.label context_label
           FROM flow_steps fs
           JOIN http_exchanges e ON e.id=fs.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id
           JOIN hosts h ON h.id=r.host_id
           LEFT JOIN exchange_identities ei ON ei.exchange_id=e.id
           LEFT JOIN identities i ON i.id=ei.identity_id
           LEFT JOIN identity_contexts ic ON ic.id=ei.context_id
           WHERE fs.id=?""", (int(step_row["id"]),)
    ).fetchone()
    item = dict(row)
    item["signature"] = _signature(item)
    item["business_values"] = _business_observations(conn, int(item["exchange_id"]))
    item["state_values"] = [x for x in item["business_values"] if x.get("is_state")]
    return item


def get_flow(conn, flow_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute(
        """SELECT f.*,i.name identity_name,c.label context_label FROM flows f
           LEFT JOIN identities i ON i.id=f.identity_id LEFT JOIN identity_contexts c ON c.id=f.context_id
           WHERE f.id=?""", (int(flow_id),)
    ).fetchone()
    if not row:
        return None
    steps = [_step_row(conn, s) for s in conn.execute("SELECT * FROM flow_steps WHERE flow_id=? ORDER BY position,id", (int(flow_id),)).fetchall()]
    transitions: list[dict[str, Any]] = []
    for prev, cur in zip(steps, steps[1:]):
        prev_states = {str(x["normalized_name"]): x for x in prev["state_values"]}
        cur_states = {str(x["normalized_name"]): x for x in cur["state_values"]}
        for name in sorted(set(prev_states) & set(cur_states)):
            av = str(prev_states[name].get("value") or "")
            bv = str(cur_states[name].get("value") or "")
            if av != bv:
                transitions.append({
                    "name": name, "from": av, "to": bv,
                    "from_step": prev["position"], "to_step": cur["position"],
                    "from_exchange": prev["exchange_id"], "to_exchange": cur["exchange_id"],
                })
    return {"flow": dict(row), "steps": steps, "transitions": transitions}


def _align_steps(a_steps: list[dict[str, Any]], b_steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sig_a = [x["signature"] for x in a_steps]
    sig_b = [x["signature"] for x in b_steps]
    matcher = SequenceMatcher(a=sig_a, b=sig_b, autojunk=False)
    aligned: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for ai, bj in zip(range(i1, i2), range(j1, j2)):
                aligned.append({"kind": "same", "a": a_steps[ai], "b": b_steps[bj]})
        elif tag == "replace":
            span = max(i2 - i1, j2 - j1)
            for off in range(span):
                aa = a_steps[i1 + off] if i1 + off < i2 else None
                bb = b_steps[j1 + off] if j1 + off < j2 else None
                aligned.append({"kind": "changed", "a": aa, "b": bb})
        elif tag == "delete":
            for ai in range(i1, i2):
                aligned.append({"kind": "only_a", "a": a_steps[ai], "b": None})
        elif tag == "insert":
            for bj in range(j1, j2):
                aligned.append({"kind": "only_b", "a": None, "b": b_steps[bj]})
    return aligned


def compare_flows(conn, flow_a: int, flow_b: int) -> dict[str, Any] | None:
    a = get_flow(conn, int(flow_a))
    b = get_flow(conn, int(flow_b))
    if not a or not b:
        return None
    aligned = _align_steps(a["steps"], b["steps"])
    for item in aligned:
        aa, bb = item.get("a"), item.get("b")
        if aa and bb:
            diff = parameter_tools.smart_diff(conn, int(aa["exchange_id"]), int(bb["exchange_id"]))
            if diff:
                item["correlations"] = (diff.get("strong_correlations") or [])[:5] + (diff.get("medium_correlations") or [])[:3]
                item["business_changes"] = [x for x in diff.get("changes", []) if x.get("business")][:8]
                item["other_change_count"] = int(diff.get("other_changes") or 0)
    return {"a": a, "b": b, "aligned": aligned}
