from __future__ import annotations

"""Evidence & provenance primitives for Negro v0.116.

The core rule is intentionally small:
- Capture Events describe *what happened and where it came from*.
- Evidence describes *what a specific experiment demonstrated*.
- Knowledge Relations are promoted conclusions backed by evidence.

Experiments never become reality merely because they returned HTTP 200.
"""

import base64
import json
import urllib.parse
from typing import Any

import negro_core as core


VALID_SEMANTIC = {"ALLOWED", "DENIED", "PARTIAL", "UNKNOWN"}
VALID_OBJECT_EVIDENCE = {"RETURNED", "NOT_RETURNED", "MODIFIED", "CREATED", "DELETED", "UNKNOWN"}
VALID_OUTCOME = {"CONFIRMED", "BLOCKED", "INCONCLUSIVE"}
VALID_EXPECTEDNESS = {"EXPECTED", "UNEXPECTED", "UNKNOWN"}


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS experiment_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            target_key TEXT NOT NULL,
            exchange_id INTEGER NOT NULL,
            object_type TEXT,
            object_value TEXT,
            transport_status INTEGER,
            semantic_result TEXT NOT NULL DEFAULT 'UNKNOWN',
            object_evidence TEXT NOT NULL DEFAULT 'UNKNOWN',
            outcome TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_experiment_evidence_event ON experiment_evidence(event_id,id);
        CREATE TABLE IF NOT EXISTS knowledge_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_key TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_ref TEXT NOT NULL,
            predicate TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_ref TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'CONFIRMED',
            expectedness TEXT NOT NULL DEFAULT 'UNKNOWN',
            evidence_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(target_key,subject_type,subject_ref,predicate,object_type,object_ref,status)
        );
        CREATE INDEX IF NOT EXISTS idx_knowledge_relations_object ON knowledge_relations(target_key,object_type,object_ref);
        CREATE INDEX IF NOT EXISTS idx_knowledge_relations_subject ON knowledge_relations(target_key,subject_type,subject_ref);
        """
    )


def _decode_b64(value: Any) -> bytes:
    if not value:
        return b""
    try:
        return base64.b64decode(str(value), validate=False)
    except Exception:
        return b""


def _split_http(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    text = raw.decode("iso-8859-1", errors="replace")
    marker = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    if marker in text:
        head, body = text.split(marker, 1)
    else:
        head, body = text, ""
    lines = head.replace("\r\n", "\n").split("\n") if head else []
    start = lines[0] if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return start, headers, body.encode("iso-8859-1", errors="replace")


def _header_map(headers: list[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers:
        out[k.lower()] = v
    return out


def _safe_body_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def _flatten(value: Any, prefix: str = "body") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out.update(_flatten(v, f"{prefix}.{k}"))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = value
    return out


def request_mutation_diff(original_b64: Any, sent_b64: Any) -> list[dict[str, Any]]:
    """Return a bounded semantic diff for a Proxy request edited before Forward."""
    original = _decode_b64(original_b64)
    sent = _decode_b64(sent_b64)
    if not original or not sent or original == sent:
        return []
    os, oh, ob = _split_http(original)
    ss, sh, sb = _split_http(sent)
    changes: list[dict[str, Any]] = []

    def add(field: str, before: Any, after: Any) -> None:
        if before == after or len(changes) >= 80:
            return
        def clip(v: Any) -> Any:
            if v is None or isinstance(v, (int, float, bool)):
                return v
            x = str(v)
            return x if len(x) <= 500 else x[:497] + "..."
        changes.append({"field": field, "before": clip(before), "after": clip(after)})

    if os != ss:
        op = os.split(" ")
        sp = ss.split(" ")
        add("request_line", os, ss)
        if len(op) >= 2 and len(sp) >= 2:
            try:
                ou = urllib.parse.urlsplit(op[1])
                su = urllib.parse.urlsplit(sp[1])
                add("path", ou.path, su.path)
                oq = dict(urllib.parse.parse_qsl(ou.query, keep_blank_values=True))
                sq = dict(urllib.parse.parse_qsl(su.query, keep_blank_values=True))
                for key in sorted(set(oq) | set(sq)):
                    add(f"query.{key}", oq.get(key), sq.get(key))
            except Exception:
                pass

    ohm, shm = _header_map(oh), _header_map(sh)
    ignored = {"content-length"}
    for key in sorted((set(ohm) | set(shm)) - ignored):
        add(f"header.{key}", ohm.get(key), shm.get(key))

    oj, sj = _safe_body_json(ob), _safe_body_json(sb)
    if oj is not None and sj is not None:
        of, sf = _flatten(oj), _flatten(sj)
        for key in sorted(set(of) | set(sf)):
            add(key, of.get(key), sf.get(key))
    elif ob != sb:
        add("body", ob.decode("utf-8", errors="replace"), sb.decode("utf-8", errors="replace"))
    return changes


def save_experiment_evidence(conn, *, event: dict[str, Any], object_type: str = "", object_value: str = "",
                             semantic_result: str = "UNKNOWN", object_evidence: str = "UNKNOWN",
                             outcome: str = "INCONCLUSIVE", notes: str = "") -> dict[str, Any]:
    init_schema(conn)
    semantic = str(semantic_result or "UNKNOWN").upper()
    obj_ev = str(object_evidence or "UNKNOWN").upper()
    out = str(outcome or "INCONCLUSIVE").upper()
    if semantic not in VALID_SEMANTIC: semantic = "UNKNOWN"
    if obj_ev not in VALID_OBJECT_EVIDENCE: obj_ev = "UNKNOWN"
    if out not in VALID_OUTCOME: out = "INCONCLUSIVE"
    now = core.now_iso()
    cur = conn.execute(
        """INSERT INTO experiment_evidence(event_id,target_key,exchange_id,object_type,object_value,transport_status,
               semantic_result,object_evidence,outcome,notes,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (int(event["id"]), str(event.get("target_key") or ""), int(event.get("exchange_id") or 0),
         str(object_type or "") or None, str(object_value or "") or None, event.get("status_code"), semantic, obj_ev, out,
         str(notes or "") or None, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM experiment_evidence WHERE id=?", (int(cur.lastrowid),)).fetchone()
    return dict(row)


def promote_relation(conn, *, target_key: str, subject_type: str, subject_ref: str, predicate: str,
                     object_type: str, object_ref: str, evidence_id: int | None,
                     expectedness: str = "UNKNOWN", status: str = "CONFIRMED") -> dict[str, Any]:
    init_schema(conn)
    exp = str(expectedness or "UNKNOWN").upper()
    if exp not in VALID_EXPECTEDNESS: exp = "UNKNOWN"
    now = core.now_iso()
    conn.execute(
        """INSERT INTO knowledge_relations(target_key,subject_type,subject_ref,predicate,object_type,object_ref,status,expectedness,evidence_id,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(target_key,subject_type,subject_ref,predicate,object_type,object_ref,status)
           DO UPDATE SET expectedness=excluded.expectedness,evidence_id=excluded.evidence_id,updated_at=excluded.updated_at""",
        (str(target_key), str(subject_type), str(subject_ref), str(predicate), str(object_type), str(object_ref),
         str(status or "CONFIRMED").upper(), exp, int(evidence_id) if evidence_id else None, now, now),
    )
    conn.commit()
    row = conn.execute(
        """SELECT * FROM knowledge_relations WHERE target_key=? AND subject_type=? AND subject_ref=? AND predicate=? AND object_type=? AND object_ref=? AND status=?""",
        (str(target_key), str(subject_type), str(subject_ref), str(predicate), str(object_type), str(object_ref), str(status or "CONFIRMED").upper()),
    ).fetchone()
    return dict(row)
