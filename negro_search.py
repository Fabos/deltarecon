from __future__ import annotations

import base64
import json
import re
import shlex
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

SEARCH_SCHEMA_VERSION = "2"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS search_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_key TEXT NOT NULL UNIQUE,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            exchange_id INTEGER,
            resource_id INTEGER,
            host_id INTEGER,
            host TEXT,
            path TEXT,
            method TEXT,
            status TEXT,
            human_state TEXT,
            signal_kind TEXT,
            preview TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_search_documents_entity ON search_documents(entity_type, entity_id);
        CREATE INDEX IF NOT EXISTS idx_search_documents_exchange ON search_documents(exchange_id);
        CREATE INDEX IF NOT EXISTS idx_search_documents_resource ON search_documents(resource_id);
        CREATE INDEX IF NOT EXISTS idx_search_documents_host ON search_documents(host_id, host);
        CREATE INDEX IF NOT EXISTS idx_search_documents_structured ON search_documents(method, status, human_state, signal_kind);

        CREATE TABLE IF NOT EXISTS saved_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            query TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(name, query)
        );
        """
    )
    # Contentless FTS keeps the searchable token index without duplicating the raw
    # HTTP bodies as a second retrievable copy in search_documents.
    conn.execute(
        """CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
               all_text,
               url_text,
               headers_text,
               cookies_text,
               params_text,
               request_text,
               response_text,
               signals_text,
               notes_text,
               content='',
               contentless_delete=1,
               tokenize='unicode61 remove_diacritics 2'
           )"""
    )
    # Trigram FTS is the substring index. It makes a plain search such as
    # `1223` match `3001112233`, and `AIza` match a longer API key, without
    # scanning raw HTTP blobs with LIKE. The regular FTS table remains useful
    # for very short (1-2 char) terms and normal token/phrase semantics.
    conn.execute(
        """CREATE VIRTUAL TABLE IF NOT EXISTS search_trigram USING fts5(
               all_text,
               url_text,
               headers_text,
               cookies_text,
               params_text,
               request_text,
               response_text,
               signals_text,
               notes_text,
               content='',
               contentless_delete=1,
               tokenize='trigram'
           )"""
    )
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('search_schema_version',?)", (SEARCH_SCHEMA_VERSION,))


def _b64_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _split_http(text: str) -> tuple[str, str]:
    if not text:
        return "", ""
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def _header_lines(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    lines = text.replace("\r\n", "\n").split("\n")
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        out.append((name.strip(), value.strip()))
    return out


def _safe_preview(text: str, limit: int = 340) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    # Hide common long opaque values in previews. They remain searchable in the
    # local FTS index because the raw exchange is already stored locally.
    text = re.sub(r"[A-Za-z0-9_+/=.-]{36,}", lambda m: f"<{len(m.group(0))} chars>", text)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _json_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)


def _state_for(conn: sqlite3.Connection, entity_type: str, entity_id: int, resource_id: int | None = None) -> str:
    row = conn.execute("SELECT state FROM entity_states WHERE entity_type=? AND entity_id=?", (entity_type, int(entity_id))).fetchone()
    if row and row["state"]:
        return str(row["state"])
    if resource_id and entity_type != "resource":
        row = conn.execute("SELECT state FROM entity_states WHERE entity_type='resource' AND entity_id=?", (int(resource_id),)).fetchone()
        if row and row["state"]:
            return str(row["state"])
    return "normal"


def _replace_doc(conn: sqlite3.Connection, meta: dict[str, Any], fields: dict[str, str]) -> int:
    init_schema(conn)
    existing = conn.execute("SELECT id FROM search_documents WHERE doc_key=?", (meta["doc_key"],)).fetchone()
    if existing:
        doc_id = int(existing["id"])
        conn.execute(
            """UPDATE search_documents SET entity_type=?,entity_id=?,exchange_id=?,resource_id=?,host_id=?,host=?,path=?,method=?,status=?,human_state=?,signal_kind=?,preview=?,updated_at=? WHERE id=?""",
            (
                meta["entity_type"], int(meta["entity_id"]), meta.get("exchange_id"), meta.get("resource_id"), meta.get("host_id"),
                meta.get("host"), meta.get("path"), meta.get("method"), meta.get("status"), meta.get("human_state"),
                meta.get("signal_kind"), meta.get("preview"), meta.get("updated_at") or now_iso(), doc_id,
            ),
        )
        conn.execute("DELETE FROM search_fts WHERE rowid=?", (doc_id,))
        conn.execute("DELETE FROM search_trigram WHERE rowid=?", (doc_id,))
    else:
        cur = conn.execute(
            """INSERT INTO search_documents(doc_key,entity_type,entity_id,exchange_id,resource_id,host_id,host,path,method,status,human_state,signal_kind,preview,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                meta["doc_key"], meta["entity_type"], int(meta["entity_id"]), meta.get("exchange_id"), meta.get("resource_id"), meta.get("host_id"),
                meta.get("host"), meta.get("path"), meta.get("method"), meta.get("status"), meta.get("human_state"),
                meta.get("signal_kind"), meta.get("preview"), meta.get("updated_at") or now_iso(),
            ),
        )
        doc_id = int(cur.lastrowid)
    values = (
        doc_id,
        fields.get("all_text", ""), fields.get("url_text", ""), fields.get("headers_text", ""), fields.get("cookies_text", ""),
        fields.get("params_text", ""), fields.get("request_text", ""), fields.get("response_text", ""), fields.get("signals_text", ""), fields.get("notes_text", ""),
    )
    conn.execute(
        """INSERT INTO search_fts(rowid,all_text,url_text,headers_text,cookies_text,params_text,request_text,response_text,signals_text,notes_text)
           VALUES(?,?,?,?,?,?,?,?,?,?)""", values,
    )
    conn.execute(
        """INSERT INTO search_trigram(rowid,all_text,url_text,headers_text,cookies_text,params_text,request_text,response_text,signals_text,notes_text)
           VALUES(?,?,?,?,?,?,?,?,?,?)""", values,
    )
    return doc_id


def index_exchange(conn: sqlite3.Connection, exchange_id: int) -> int | None:
    init_schema(conn)
    row = conn.execute(
        """SELECT e.*,o.method,o.resource_id,r.host_id,r.url,r.path,h.hostname
           FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id
           JOIN hosts h ON h.id=r.host_id
           WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return None
    req = _b64_text(row["request_b64"])
    resp = _b64_text(row["response_b64"])
    req_head, req_body = _split_http(req)
    resp_head, resp_body = _split_http(resp)
    req_headers = _header_lines(req_head)
    resp_headers = _header_lines(resp_head)
    headers_text = "\n".join(f"{k}: {v}" for k, v in req_headers + resp_headers)
    cookies_text = "\n".join(f"{k}: {v}" for k, v in req_headers + resp_headers if k.lower() in {"cookie", "set-cookie"})
    try:
        q = json.loads(row["query_json"] or "{}")
    except Exception:
        q = row["query_json"] or ""
    params = [dict(x) for x in conn.execute(
        "SELECT name,normalized_name,location,value_preview,value_raw FROM parameter_observations WHERE exchange_id=? ORDER BY id",
        (int(exchange_id),),
    ).fetchall()]
    params_text = _json_text(q) + "\n" + "\n".join(
        f"{p['location']} {p['name']} {p['normalized_name']} {p.get('value_raw') or p['value_preview'] or ''}" for p in params
    )
    signals = [dict(x) for x in conn.execute(
        "SELECT kind,category,title,why_json,evidence_json FROM signal_occurrences WHERE exchange_id=? AND dismissed_at IS NULL ORDER BY id",
        (int(exchange_id),),
    ).fetchall()]
    signal_text = "\n".join(
        " ".join(str(x.get(k) or "") for k in ("kind", "category", "title", "why_json", "evidence_json")) for x in signals
    )
    notes = [str(x["body"] or "") for x in conn.execute(
        "SELECT body FROM notes WHERE (entity_type='resource' AND entity_id=?) OR (entity_type='exchange' AND entity_id=?) ORDER BY id",
        (int(row["resource_id"]), int(exchange_id)),
    ).fetchall()]
    state = _state_for(conn, "exchange", int(exchange_id), int(row["resource_id"]))
    url_text = f"{row['hostname']} {row['url']} {row['path']} {row['method']} {row['status_code'] or ''}"
    all_text = "\n".join([
        url_text, headers_text, cookies_text, params_text, req_body, resp_body, signal_text, "\n".join(notes), state,
    ])
    preview_source = resp_body or req_body or url_text
    kinds = sorted({str(x.get("kind") or x.get("category") or "") for x in signals if x.get("kind") or x.get("category")})
    return _replace_doc(
        conn,
        {
            "doc_key": f"exchange:{exchange_id}", "entity_type": "exchange", "entity_id": int(exchange_id), "exchange_id": int(exchange_id),
            "resource_id": int(row["resource_id"]), "host_id": int(row["host_id"]), "host": str(row["hostname"]), "path": str(row["path"] or "/"),
            "method": str(row["method"] or ""), "status": str(row["status_code"] or ""), "human_state": state,
            "signal_kind": ",".join(kinds), "preview": _safe_preview(preview_source), "updated_at": str(row["last_seen_at"] or now_iso()),
        },
        {
            "all_text": all_text, "url_text": url_text, "headers_text": headers_text, "cookies_text": cookies_text, "params_text": params_text,
            "request_text": req_body, "response_text": resp_body, "signals_text": signal_text, "notes_text": "\n".join(notes),
        },
    )


def index_resource(conn: sqlite3.Connection, resource_id: int) -> int | None:
    row = conn.execute("SELECT r.*,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?", (int(resource_id),)).fetchone()
    if not row:
        return None
    notes = [str(x["body"] or "") for x in conn.execute("SELECT body FROM notes WHERE entity_type='resource' AND entity_id=? ORDER BY id", (int(resource_id),)).fetchall()]
    signals = [dict(x) for x in conn.execute("SELECT kind,category,title,why_json,evidence_json FROM signal_occurrences WHERE resource_id=? AND dismissed_at IS NULL ORDER BY id", (int(resource_id),)).fetchall()]
    signal_text = "\n".join(" ".join(str(x.get(k) or "") for k in ("kind", "category", "title", "why_json", "evidence_json")) for x in signals)
    methods = [str(x["method"] or "") for x in conn.execute("SELECT method FROM resource_operations WHERE resource_id=? ORDER BY method", (int(resource_id),)).fetchall()]
    state = _state_for(conn, "resource", int(resource_id))
    url_text = f"{row['hostname']} {row['url']} {row['path']} {' '.join(methods)}"
    all_text = "\n".join([url_text, signal_text, "\n".join(notes), state, str(row["classification"] or "")])
    kinds = sorted({str(x.get("kind") or x.get("category") or "") for x in signals if x.get("kind") or x.get("category")})
    return _replace_doc(conn, {
        "doc_key": f"resource:{resource_id}", "entity_type": "resource", "entity_id": int(resource_id), "resource_id": int(resource_id), "host_id": int(row["host_id"]),
        "host": str(row["hostname"]), "path": str(row["path"] or "/"), "method": ",".join(methods), "status": "", "human_state": state,
        "signal_kind": ",".join(kinds), "preview": _safe_preview(str(row["url"])), "updated_at": str(row["updated_at"] or now_iso()),
    }, {"all_text": all_text, "url_text": url_text, "signals_text": signal_text, "notes_text": "\n".join(notes)})


def index_host(conn: sqlite3.Connection, host_id: int) -> int | None:
    row = conn.execute("SELECT * FROM hosts WHERE id=?", (int(host_id),)).fetchone()
    if not row:
        return None
    notes = [str(x["body"] or "") for x in conn.execute("SELECT body FROM notes WHERE entity_type='host' AND entity_id=? ORDER BY id", (int(host_id),)).fetchall()]
    state = _state_for(conn, "host", int(host_id))
    text = "\n".join([str(row["hostname"]), state, str(row["classification"] or ""), str(row["priority"] or ""), "\n".join(notes)])
    return _replace_doc(conn, {
        "doc_key": f"host:{host_id}", "entity_type": "host", "entity_id": int(host_id), "host_id": int(host_id), "host": str(row["hostname"]),
        "path": "", "method": "", "status": "", "human_state": state, "signal_kind": "", "preview": str(row["hostname"]), "updated_at": str(row["updated_at"] or now_iso()),
    }, {"all_text": text, "url_text": str(row["hostname"]), "notes_text": "\n".join(notes)})


def index_knowledge(conn: sqlite3.Connection) -> int:
    count = 0
    # AI hypotheses
    for row in conn.execute("SELECT * FROM leads_v2 WHERE upper(COALESCE(source,''))='AI' ORDER BY id").fetchall():
        text = "\n".join(str(row[k] or "") for k in ("title", "lead_type", "why_interesting", "next_test", "confirm_if", "discard_if", "result_notes"))
        _replace_doc(conn, {
            "doc_key": f"hypothesis:{row['id']}", "entity_type": "hypothesis", "entity_id": int(row["id"]), "resource_id": row["resource_id"], "host_id": row["host_id"],
            "host": "", "path": "", "method": "", "status": str(row["status"] or ""), "human_state": str(row["status"] or ""), "signal_kind": str(row["lead_type"] or ""),
            "preview": _safe_preview(str(row["why_interesting"] or row["title"])), "updated_at": str(row["updated_at"] or now_iso()),
        }, {"all_text": text, "signals_text": str(row["lead_type"] or ""), "notes_text": str(row["result_notes"] or "")})
        count += 1
    for row in conn.execute("SELECT * FROM investigations ORDER BY id").fetchall():
        text = "\n".join(str(row[k] or "") for k in ("title", "category", "status", "summary", "notes"))
        _replace_doc(conn, {
            "doc_key": f"investigation:{row['id']}", "entity_type": "investigation", "entity_id": int(row["id"]), "host": "", "path": "", "method": "", "status": str(row["status"] or ""),
            "human_state": str(row["status"] or ""), "signal_kind": str(row["category"] or ""), "preview": _safe_preview(str(row["summary"] or row["title"])), "updated_at": str(row["updated_at"] or now_iso()),
        }, {"all_text": text, "signals_text": str(row["category"] or ""), "notes_text": str(row["notes"] or "")})
        count += 1
    for row in conn.execute("SELECT * FROM findings ORDER BY id").fetchall():
        notes = [str(x["body"] or "") for x in conn.execute("SELECT body FROM notes WHERE entity_type='finding' AND entity_id=? ORDER BY id", (int(row["id"]),)).fetchall()]
        text = "\n".join([str(row[k] or "") for k in ("title", "severity", "status", "description", "impact", "remediation")] + notes)
        _replace_doc(conn, {
            "doc_key": f"finding:{row['id']}", "entity_type": "finding", "entity_id": int(row["id"]), "host": "", "path": "", "method": "", "status": str(row["status"] or ""),
            "human_state": "finding", "signal_kind": "finding", "preview": _safe_preview(str(row["description"] or row["title"])), "updated_at": str(row["updated_at"] or now_iso()),
        }, {"all_text": text, "signals_text": "finding " + str(row["severity"] or ""), "notes_text": "\n".join(notes)})
        count += 1
    # Identity/context names are user-provided knowledge and are safe to index.
    try:
        import negro_identity as identity_tools
        identity_tools.init_schema(conn)
        for row in conn.execute("SELECT * FROM identities ORDER BY id").fetchall():
            ctx = [dict(x) for x in conn.execute("SELECT label,role,tenant,notes FROM identity_contexts WHERE identity_id=? ORDER BY id", (int(row["id"]),)).fetchall()]
            ctx_text = "\n".join(" ".join(str(x.get(k) or "") for k in ("label","role","tenant","notes")) for x in ctx)
            text = "\n".join([str(row["name"] or ""), str(row["kind"] or ""), str(row["notes"] or ""), ctx_text])
            _replace_doc(conn, {
                "doc_key": f"identity:{row['id']}", "entity_type": "identity", "entity_id": int(row["id"]), "host": "", "path": "", "method": "", "status": "",
                "human_state": "", "signal_kind": "identity", "preview": _safe_preview(ctx_text or str(row["notes"] or row["name"])), "updated_at": str(row["updated_at"] or now_iso()),
            }, {"all_text": text, "notes_text": text})
            count += 1
    except Exception:
        pass
    return count


def rebuild_search_index(conn: sqlite3.Connection) -> dict[str, int]:
    init_schema(conn)
    conn.execute("DELETE FROM search_fts")
    conn.execute("DELETE FROM search_trigram")
    conn.execute("DELETE FROM search_documents")
    hosts = [int(x["id"]) for x in conn.execute("SELECT id FROM hosts ORDER BY id").fetchall()]
    resources = [int(x["id"]) for x in conn.execute("SELECT id FROM resources ORDER BY id").fetchall()]
    exchanges = [int(x["id"]) for x in conn.execute("SELECT id FROM http_exchanges ORDER BY id").fetchall()]
    for hid in hosts:
        index_host(conn, hid)
    for rid in resources:
        index_resource(conn, rid)
    for eid in exchanges:
        index_exchange(conn, eid)
    knowledge = index_knowledge(conn)
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('search_rebuilt_at',?)", (now_iso(),))
    return {"hosts": len(hosts), "resources": len(resources), "exchanges": len(exchanges), "knowledge": knowledge, "documents": len(hosts) + len(resources) + len(exchanges) + knowledge}


def search_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    init_schema(conn)
    documents = int(conn.execute("SELECT COUNT(*) c FROM search_documents").fetchone()["c"] or 0)
    exchanges = int(conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"] or 0)
    trigram_documents = int(conn.execute("SELECT COUNT(*) c FROM search_trigram").fetchone()["c"] or 0)
    rebuilt = conn.execute("SELECT value FROM meta WHERE key='search_rebuilt_at'").fetchone()
    version = conn.execute("SELECT value FROM meta WHERE key='search_schema_version'").fetchone()
    return {
        "documents": documents,
        "http_exchanges": exchanges,
        "trigram_documents": trigram_documents,
        "rebuilt_at": rebuilt["value"] if rebuilt else None,
        "schema_version": version["value"] if version else None,
        "needs_reindex": documents > 0 and trigram_documents < documents,
    }


FILTER_ALIASES = {
    "host": "host", "method": "method", "status": "status", "state": "state", "type": "type",
    "signal": "signal", "param": "param", "cookie": "cookie", "header": "header", "body": "body",
    "request": "request", "response": "response", "contains": "contains", "path": "path",
}


@dataclass
class ParsedQuery:
    raw: str
    text_terms: list[tuple[str, str]]
    filters: dict[str, list[str]]
    errors: list[str]


def parse_query(query: str) -> ParsedQuery:
    query = str(query or "").strip()
    if not query:
        return ParsedQuery(query, [], {}, [])
    try:
        tokens = shlex.split(query)
    except ValueError as exc:
        return ParsedQuery(query, [], {}, [f"Comillas incompletas: {exc}"])
    terms: list[tuple[str, str]] = []
    filters: dict[str, list[str]] = {}
    errors: list[str] = []
    for token in tokens:
        if ":" in token:
            key, value = token.split(":", 1)
            key = key.lower().strip()
            if key in FILTER_ALIASES:
                value = value.strip()
                if not value:
                    errors.append(f"{key}: requiere un valor")
                    continue
                if key in {"host", "method", "status", "state", "type"}:
                    filters.setdefault(key, []).append(value)
                else:
                    terms.append((key, value))
                continue
        terms.append(("contains", token))
    return ParsedQuery(query, terms, filters, errors)


def _fts_quote(value: str) -> str:
    # FTS5 phrase; double quotes inside phrases are escaped by doubling them.
    return '"' + str(value).replace('"', '""') + '"'


def _fts_expr(terms: Iterable[tuple[str, str]]) -> str:
    parts: list[str] = []
    col_map = {
        "signal": "signals_text", "param": "params_text", "cookie": "cookies_text", "header": "headers_text",
        "request": "request_text", "response": "response_text", "path": "url_text",
    }
    for kind, value in terms:
        phrase = _fts_quote(value)
        if kind == "body":
            parts.append(f"{{request_text response_text}}:{phrase}")
        elif kind in col_map:
            parts.append(f"{col_map[kind]}:{phrase}")
        else:
            parts.append(phrase)
    return " AND ".join(parts)


def _is_trigram_term(value: str) -> bool:
    # FTS5 trigram needs at least 3 unicode characters to constrain a MATCH.
    # Spaces/punctuation still count because the trigram tokenizer indexes them.
    return len(str(value or "")) >= 3


def search(conn: sqlite3.Connection, query: str, limit: int = 100) -> dict[str, Any]:
    """Search structured metadata plus substring-capable local FTS indexes.

    Free text and text-field filters use trigram matching by default for terms of
    three or more characters, so a fragment can be found inside a larger value.
    Example: `1223` matches `3001112233`; `response:AIza` matches a longer key.
    One/two-character terms fall back to the regular unicode token index.
    """
    init_schema(conn)
    parsed = parse_query(query)
    if parsed.errors:
        return {"query": query, "parsed": parsed, "results": [], "error": "; ".join(parsed.errors), "count": 0}

    tri_terms = [(k, v) for k, v in parsed.text_terms if _is_trigram_term(v)]
    word_terms = [(k, v) for k, v in parsed.text_terms if not _is_trigram_term(v)]
    tri_fts = _fts_expr(tri_terms)
    word_fts = _fts_expr(word_terms)

    joins: list[str] = []
    where: list[str] = []
    params: list[Any] = []
    rank_parts: list[str] = []
    if tri_fts:
        joins.append("JOIN search_trigram st ON st.rowid=d.id")
        where.append("search_trigram MATCH ?")
        params.append(tri_fts)
        rank_parts.append("bm25(search_trigram,1.0,1.2,0.7,0.8,1.0,1.0,1.0,1.1,0.8)")
    if word_fts:
        joins.append("JOIN search_fts sf ON sf.rowid=d.id")
        where.append("search_fts MATCH ?")
        params.append(word_fts)
        rank_parts.append("bm25(search_fts,1.0,1.2,0.7,0.8,1.0,1.0,1.0,1.1,0.8)")

    for key, values in parsed.filters.items():
        if not values:
            continue
        clauses = []
        for value in values:
            if key == "host":
                clauses.append("lower(COALESCE(d.host,'')) LIKE ?"); params.append(f"%{value.lower()}%")
            elif key == "method":
                clauses.append("upper(COALESCE(d.method,'')) LIKE ?"); params.append(f"%{value.upper()}%")
            elif key == "status":
                clauses.append("COALESCE(d.status,'') = ?"); params.append(str(value))
            elif key == "state":
                clauses.append("lower(COALESCE(d.human_state,'')) = ?"); params.append(value.lower())
            elif key == "type":
                clauses.append("lower(COALESCE(d.entity_type,'')) = ?"); params.append(value.lower())
        if clauses:
            where.append("(" + " OR ".join(clauses) + ")")

    rank_sql = " + ".join(rank_parts) if rank_parts else "0.0"
    sql = f"SELECT d.*, ({rank_sql}) AS rank FROM search_documents d {' '.join(joins)}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY rank ASC, d.updated_at DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    return {
        "query": query,
        "parsed": parsed,
        "results": rows,
        "error": None,
        "count": len(rows),
        "fts": tri_fts or word_fts,
        "match_mode": "substring" if tri_fts else "token",
    }

def save_search(conn: sqlite3.Connection, name: str, query: str) -> int:
    init_schema(conn)
    name = str(name or "").strip()[:120]
    query = str(query or "").strip()[:2000]
    if not name or not query:
        raise ValueError("Nombre y consulta son obligatorios")
    now = now_iso()
    row = conn.execute("SELECT id FROM saved_searches WHERE name=? AND query=?", (name, query)).fetchone()
    if row:
        conn.execute("UPDATE saved_searches SET updated_at=? WHERE id=?", (now, int(row["id"])))
        return int(row["id"])
    cur = conn.execute("INSERT INTO saved_searches(name,query,created_at,updated_at) VALUES(?,?,?,?)", (name, query, now, now))
    return int(cur.lastrowid)


def list_saved_searches(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute("SELECT * FROM saved_searches ORDER BY updated_at DESC,id DESC LIMIT 100").fetchall()]


def delete_saved_search(conn: sqlite3.Connection, search_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM saved_searches WHERE id=?", (int(search_id),))
