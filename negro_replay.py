from __future__ import annotations

import base64
import difflib
import json
import re
from datetime import datetime, timezone
from typing import Any

import negro_identity as identity_tools


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS authorization_replays (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_exchange_id INTEGER NOT NULL,
            original_identity_id INTEGER,
            original_context_id INTEGER,
            replay_identity_id INTEGER,
            replay_context_id INTEGER,
            prepared_request_b64 TEXT NOT NULL,
            queue_id INTEGER,
            status TEXT NOT NULL DEFAULT 'prepared',
            safety_class TEXT NOT NULL DEFAULT 'state_changing',
            safety_reason TEXT,
            target_objects_json TEXT NOT NULL DEFAULT '[]',
            flow_context_json TEXT NOT NULL DEFAULT '[]',
            auth_changes_json TEXT NOT NULL DEFAULT '[]',
            response_b64 TEXT,
            response_status INTEGER,
            response_size INTEGER NOT NULL DEFAULT 0,
            elapsed_ms INTEGER,
            comparison_json TEXT NOT NULL DEFAULT '{}',
            test_validity TEXT NOT NULL DEFAULT 'pending',
            decision TEXT,
            notes TEXT,
            hypothesis_id INTEGER,
            investigation_id INTEGER,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            completed_at TEXT,
            FOREIGN KEY(original_exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
            FOREIGN KEY(original_identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(original_context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL,
            FOREIGN KEY(replay_identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(replay_context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL,
            FOREIGN KEY(queue_id) REFERENCES burp_repeater_queue(id) ON DELETE SET NULL,
            FOREIGN KEY(hypothesis_id) REFERENCES leads_v2(id) ON DELETE SET NULL,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auth_replay_original ON authorization_replays(original_exchange_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_auth_replay_queue ON authorization_replays(queue_id);
        CREATE INDEX IF NOT EXISTS idx_auth_replay_hypothesis ON authorization_replays(hypothesis_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_auth_replay_investigation ON authorization_replays(investigation_id, created_at);
        """
    )


def _decode_b64_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("iso-8859-1", errors="replace")
    except Exception:
        return ""


def _encode_raw(value: str) -> str:
    return base64.b64encode(value.encode("iso-8859-1", errors="replace")).decode("ascii")


def _split_http(raw: str) -> tuple[str, str]:
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)
    if "\n\n" in raw:
        return raw.split("\n\n", 1)
    return raw, ""


def _headers(raw: str) -> dict[str, str]:
    head, _ = _split_http(raw)
    out: dict[str, str] = {}
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip().lower()] = v.strip()
    return out


def _body(raw: str) -> str:
    return _split_http(raw)[1]


def _json_shape(text: str) -> Any:
    try:
        obj = json.loads(text)
    except Exception:
        return None
    def shape(v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): shape(v[k]) for k in sorted(v)}
        if isinstance(v, list):
            return [shape(v[0])] if v else []
        if v is None: return "null"
        if isinstance(v, bool): return "bool"
        if isinstance(v, (int, float)): return "number"
        return "string"
    return shape(obj)


def classify_request(method: str, path: str, request_raw: str = "") -> tuple[str, str]:
    m = str(method or "GET").upper()
    p = str(path or "").lower()
    if m in {"GET", "HEAD", "OPTIONS"}:
        return "replay_safe", "La request parece de lectura. Aun así, confirma que el endpoint no tenga efectos laterales."
    state_tokens = (
        "otp", "verify", "confirm", "redeem", "consume", "activate", "complete", "finalize",
        "password-reset", "password_reset", "reset-password", "payment/confirm", "order/confirm",
        "coupon", "token/verify", "magic-link", "magic_link",
    )
    if any(t in p for t in state_tokens):
        return "state_dependent", "La operación parece depender de estado previo o ser de un solo uso. Un resultado negativo puede ser inconcluso."
    return "state_changing", "Esta request puede modificar estado en la aplicación. Revísala antes de enviarla."


def _identity_row(conn, identity_id: int | None, context_id: int | None = None) -> dict[str, Any] | None:
    if not identity_id:
        return None
    row = conn.execute("SELECT id,name,kind FROM identities WHERE id=?", (int(identity_id),)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["context_id"] = context_id
    out["context_label"] = None
    if context_id:
        c = conn.execute("SELECT label,role,tenant FROM identity_contexts WHERE id=? AND identity_id=?", (int(context_id), int(identity_id))).fetchone()
        if c:
            out.update({"context_label": c["label"], "role": c["role"], "tenant": c["tenant"]})
    return out


def _objects_for_exchange(conn, exchange_id: int) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(
            """SELECT DISTINCT bo.id,bt.name object_type,bo.identifier_raw,bo.identifier_preview,bi.normalized_name
                 FROM business_object_observations boo
                 JOIN business_objects bo ON bo.id=boo.business_object_id
                 JOIN business_object_types bt ON bt.id=bo.object_type_id
                 JOIN business_object_identifiers bi ON bi.id=boo.identifier_id
                 WHERE boo.exchange_id=? ORDER BY bt.name,bo.id""",
            (int(exchange_id),),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _flows_for_exchange(conn, exchange_id: int) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(
            """SELECT f.id,f.name,fs.position,fs.label,
                      (SELECT COUNT(*) FROM flow_steps x WHERE x.flow_id=f.id AND x.position<fs.position) previous_steps
                 FROM flow_steps fs JOIN flows f ON f.id=fs.flow_id
                 WHERE fs.exchange_id=? ORDER BY f.id,fs.position""", (int(exchange_id),)
        ).fetchall()
        out=[]
        for row in rows:
            item=dict(row)
            prev=conn.execute(
                """SELECT fs.position,fs.label,o.method,r.path FROM flow_steps fs
                     JOIN http_exchanges e ON e.id=fs.exchange_id
                     JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
                     WHERE fs.flow_id=? AND fs.position<? ORDER BY fs.position""",
                (int(row["id"]), int(row["position"])),
            ).fetchall()
            item["previous"]=[dict(x) for x in prev]
            out.append(item)
        return out
    except Exception:
        return []


def _auth_changes(conn, exchange_id: int, identity_id: int | None, context_id: int | None) -> list[dict[str, Any]]:
    original = identity_tools.extract_auth_materials(conn, int(exchange_id))
    target = identity_tools.current_auth_materials(conn, int(identity_id), context_id=context_id) if identity_id else []
    def slot(m: dict[str, Any]) -> tuple[str, str]:
        typ=str(m.get("material_type") or "")
        # bearer/authorization are one request slot regardless of stored scheme label.
        if typ in {"bearer","authorization"}: return ("authorization","authorization")
        return (typ, str(m.get("name") or m.get("material_name") or "").lower())
    o={slot(m):m for m in original}
    t={slot(m):m for m in target}
    changes=[]
    # Replay intentionally replaces only auth mechanisms present in the original
    # request.  Business IDs and unrelated headers/cookies stay untouched.
    for key,before in o.items():
        after=t.get(key)
        if identity_id is None:
            changes.append({"type":key[0],"name":before.get("name") or before.get("material_name"),"before":before.get("preview") or before.get("masked_preview"),"after":"(eliminado)"})
        elif after:
            changes.append({"type":key[0],"name":after.get("material_name") or after.get("name") or before.get("name"),"before":before.get("preview") or before.get("masked_preview"),"after":after.get("masked_preview") or after.get("preview")})
    return changes

def prepare_context(conn, exchange_id: int, replay_identity_id: int | None, *, replay_context_id: int | None = None) -> dict[str, Any]:
    init_schema(conn)
    row = conn.execute(
        """SELECT e.*,o.method,r.path,r.url FROM http_exchanges e
             JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
             WHERE e.id=?""", (int(exchange_id),)
    ).fetchone()
    if not row:
        raise ValueError("Request original no encontrada")
    original_assignment = conn.execute("SELECT identity_id,context_id FROM exchange_identities WHERE exchange_id=?", (int(exchange_id),)).fetchone()
    original_identity_id = int(original_assignment["identity_id"]) if original_assignment and original_assignment["identity_id"] else None
    original_context_id = int(original_assignment["context_id"]) if original_assignment and original_assignment["context_id"] else None
    rewritten = identity_tools.rewrite_exchange_as_identity(conn, int(exchange_id), int(replay_identity_id) if replay_identity_id else None, context_id=replay_context_id, match_original_mechanism=True)
    original_raw = _decode_b64_text(row["request_b64"])
    prepared_raw = _decode_b64_text(rewritten["request_b64"])
    safety_class, safety_reason = classify_request(str(row["method"]), str(row["path"]), prepared_raw)
    return {
        "exchange": dict(row),
        "original_identity": _identity_row(conn, original_identity_id, original_context_id),
        "replay_identity": _identity_row(conn, replay_identity_id, replay_context_id) if replay_identity_id else {"id":None,"name":"Sin autenticación","context_id":None,"context_label":None},
        "original_identity_id": original_identity_id,
        "original_context_id": original_context_id,
        "replay_identity_id": replay_identity_id,
        "replay_context_id": replay_context_id,
        "prepared_request_b64": rewritten["request_b64"],
        "prepared_request_text": prepared_raw,
        "original_request_text": original_raw,
        "original_response_text": _decode_b64_text(row["response_b64"]),
        "auth_changes": _auth_changes(conn, int(exchange_id), replay_identity_id, replay_context_id),
        "objects": _objects_for_exchange(conn, int(exchange_id)),
        "flows": _flows_for_exchange(conn, int(exchange_id)),
        "safety_class": safety_class,
        "safety_reason": safety_reason,
        "auth_mechanism_matched": bool(rewritten.get("auth_mechanism_matched", True)),
    }


def create_replay(conn, exchange_id: int, replay_identity_id: int | None, *, replay_context_id: int | None = None,
                  hypothesis_id: int | None = None, investigation_id: int | None = None, notes: str = "") -> int:
    ctx = prepare_context(conn, int(exchange_id), replay_identity_id, replay_context_id=replay_context_id)
    now=now_iso()
    cur=conn.execute(
        """INSERT INTO authorization_replays(original_exchange_id,original_identity_id,original_context_id,replay_identity_id,replay_context_id,
               prepared_request_b64,status,safety_class,safety_reason,target_objects_json,flow_context_json,auth_changes_json,test_validity,notes,hypothesis_id,investigation_id,created_at)
             VALUES(?,?,?,?,?,?,'prepared',?,?,?,?,?,'pending',?,?,?,?)""",
        (int(exchange_id),ctx["original_identity_id"],ctx["original_context_id"],replay_identity_id,replay_context_id,ctx["prepared_request_b64"],
         ctx["safety_class"],ctx["safety_reason"],json.dumps(ctx["objects"],ensure_ascii=False),json.dumps(ctx["flows"],ensure_ascii=False),json.dumps(ctx["auth_changes"],ensure_ascii=False),
         str(notes or "")[:4000],hypothesis_id,investigation_id,now),
    )
    return int(cur.lastrowid)


def get_replay(conn, replay_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row=conn.execute(
        """SELECT ar.*,e.status_code original_status,e.response_size original_response_size,o.method,r.path,r.url,
                  oi.name original_identity_name,ri.name replay_identity_name,oc.label original_context_label,rc.label replay_context_label
             FROM authorization_replays ar JOIN http_exchanges e ON e.id=ar.original_exchange_id
             JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
             LEFT JOIN identities oi ON oi.id=ar.original_identity_id LEFT JOIN identities ri ON ri.id=ar.replay_identity_id
             LEFT JOIN identity_contexts oc ON oc.id=ar.original_context_id LEFT JOIN identity_contexts rc ON rc.id=ar.replay_context_id
             WHERE ar.id=?""", (int(replay_id),)
    ).fetchone()
    if not row: return None
    out=dict(row)
    for key in ("target_objects_json","flow_context_json","auth_changes_json","comparison_json"):
        try: out[key[:-5] if key.endswith('_json') else key]=json.loads(out.get(key) or ('[]' if key!='comparison_json' else '{}'))
        except Exception: out[key[:-5] if key.endswith('_json') else key]=[] if key!='comparison_json' else {}
    out["prepared_request_text"]=_decode_b64_text(out.get("prepared_request_b64"))
    out["response_text"]=_decode_b64_text(out.get("response_b64"))
    orig=conn.execute("SELECT request_b64,response_b64 FROM http_exchanges WHERE id=?",(int(out["original_exchange_id"]),)).fetchone()
    out["original_request_text"]=_decode_b64_text(orig["request_b64"] if orig else None)
    out["original_response_text"]=_decode_b64_text(orig["response_b64"] if orig else None)
    return out


def queue_replay(conn, replay_id: int, *, request_text: str | None = None) -> dict[str, Any]:
    replay=get_replay(conn,int(replay_id))
    if not replay: raise ValueError("Replay no encontrado")
    if replay["status"] in {"queued","completed"}: raise ValueError("Este Replay ya fue enviado")
    request_b64=_encode_raw(request_text) if request_text is not None else str(replay["prepared_request_b64"])
    caption_identity = replay.get("replay_identity_name") or "Sin autenticación"
    caption=f"Negro Replay · {caption_identity} · {replay['method']} {replay['path']}"
    resource=conn.execute("SELECT o.resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?",(int(replay['original_exchange_id']),)).fetchone()
    cur=conn.execute(
        """INSERT INTO burp_repeater_queue(resource_id,method,url,request_b64,caption,status,created_at,job_kind)
             VALUES(?,?,?,?,?,'pending',?,'replay_execute')""",
        (int(resource["resource_id"]),replay["method"],replay["url"],request_b64,caption,now_iso()),
    )
    qid=int(cur.lastrowid); now=now_iso()
    conn.execute("UPDATE authorization_replays SET prepared_request_b64=?,queue_id=?,status='queued',sent_at=? WHERE id=?",(request_b64,qid,now,int(replay_id)))
    return {"replay_id":int(replay_id),"queue_id":qid,"status":"queued"}


def _compare_responses(original_raw: str, replay_raw: str, original_status: int | None, replay_status: int | None, elapsed_ms: int | None) -> dict[str, Any]:
    obody=_body(original_raw); rbody=_body(replay_raw)
    sim=round(difflib.SequenceMatcher(None, obody, rbody).ratio()*100.0,1) if (obody or rbody) else 100.0
    oh=_headers(original_raw); rh=_headers(replay_raw)
    relevant=[]
    for key in ("location","content-type","www-authenticate","set-cookie","cache-control"):
        if oh.get(key)!=rh.get(key): relevant.append({"header":key,"original":oh.get(key),"replay":rh.get(key)})
    os=_json_shape(obody); rs=_json_shape(rbody)
    return {
        "original_status":original_status,"replay_status":replay_status,
        "original_size":len(original_raw.encode('iso-8859-1',errors='replace')) if original_raw else 0,
        "replay_size":len(replay_raw.encode('iso-8859-1',errors='replace')) if replay_raw else 0,
        "body_similarity_pct":sim,"relevant_header_differences":relevant,
        "json_structure_equal": (os==rs) if os is not None and rs is not None else None,
        "original_json_shape":os,"replay_json_shape":rs,"elapsed_ms":elapsed_ms,
    }


def complete_from_queue(conn, queue_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    replay_row=conn.execute("SELECT id,safety_class,original_exchange_id FROM authorization_replays WHERE queue_id=?",(int(queue_id),)).fetchone()
    if not replay_row: return None
    queue=conn.execute("SELECT * FROM burp_repeater_queue WHERE id=?",(int(queue_id),)).fetchone()
    orig=conn.execute("SELECT response_b64,status_code FROM http_exchanges WHERE id=?",(int(replay_row['original_exchange_id']),)).fetchone()
    if not queue: return None
    ok=str(queue["status"] or "")=='done'
    replay_status=int(queue["response_status"]) if queue["response_status"] is not None else None
    if not ok:
        validity='transport_error'
    elif replay_row['safety_class']=='state_dependent' and replay_status in {409,410,412,422}:
        validity='state_invalid'
    elif replay_status in {401,403}:
        validity='denied'
    elif replay_status is not None and 200 <= replay_status < 300:
        validity='allowed'
    else:
        validity='inconclusive'
    orig_raw=_decode_b64_text(orig["response_b64"] if orig else None)
    replay_raw=_decode_b64_text(queue["response_b64"])
    comparison=_compare_responses(orig_raw,replay_raw,int(orig["status_code"]) if orig and orig["status_code"] is not None else None,replay_status,int(queue["elapsed_ms"] or 0) or None)
    conn.execute(
        """UPDATE authorization_replays SET status=?,response_b64=?,response_status=?,response_size=?,elapsed_ms=?,comparison_json=?,test_validity=?,completed_at=? WHERE id=?""",
        ('completed' if ok else 'error',queue['response_b64'],replay_status,len(base64.b64decode(queue['response_b64'])) if queue['response_b64'] else 0,queue['elapsed_ms'],json.dumps(comparison,ensure_ascii=False),validity,now_iso(),int(replay_row['id']))
    )
    return get_replay(conn,int(replay_row['id']))


def update_replay(conn, replay_id: int, *, test_validity: str | None = None, decision: str | None = None, notes: str | None = None,
                  hypothesis_id: int | None = None, investigation_id: int | None = None) -> None:
    allowed={"pending","allowed","denied","inconclusive","transport_error","state_invalid"}
    fields=[]; params=[]
    if test_validity is not None:
        if test_validity not in allowed: raise ValueError("Estado de prueba inválido")
        fields.append('test_validity=?'); params.append(test_validity)
    if decision is not None: fields.append('decision=?'); params.append(str(decision)[:120])
    if notes is not None: fields.append('notes=?'); params.append(str(notes)[:5000])
    if hypothesis_id is not None: fields.append('hypothesis_id=?'); params.append(int(hypothesis_id) if hypothesis_id else None)
    if investigation_id is not None: fields.append('investigation_id=?'); params.append(int(investigation_id) if investigation_id else None)
    if not fields: return
    params.append(int(replay_id)); conn.execute(f"UPDATE authorization_replays SET {','.join(fields)} WHERE id=?",params)


def list_replays(conn, *, investigation_id: int | None = None, hypothesis_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_schema(conn)
    where=[]; params=[]
    if investigation_id is not None: where.append('ar.investigation_id=?'); params.append(int(investigation_id))
    if hypothesis_id is not None: where.append('ar.hypothesis_id=?'); params.append(int(hypothesis_id))
    clause=('WHERE '+' AND '.join(where)) if where else ''
    rows=conn.execute(
        f"""SELECT ar.*,o.method,r.path,oi.name original_identity_name,ri.name replay_identity_name
              FROM authorization_replays ar JOIN http_exchanges e ON e.id=ar.original_exchange_id
              JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
              LEFT JOIN identities oi ON oi.id=ar.original_identity_id LEFT JOIN identities ri ON ri.id=ar.replay_identity_id
              {clause} ORDER BY ar.created_at DESC,ar.id DESC LIMIT ?""",(*params,max(1,min(int(limit),500)))
    ).fetchall()
    return [dict(r) for r in rows]

def _token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def observed_owner_identity(conn, exchange_id: int) -> dict[str, Any] | None:
    aliases: dict[str, set[int]] = {}
    for row in conn.execute("SELECT id,name FROM identities").fetchall():
        t=_token(row["name"])
        if len(t)>=3: aliases.setdefault(t,set()).add(int(row["id"]))
    for row in conn.execute("SELECT identity_id,value_raw,value_preview FROM identity_resolvers WHERE enabled=1").fetchall():
        t=_token(row["value_raw"] or row["value_preview"])
        if len(t)>=3: aliases.setdefault(t,set()).add(int(row["identity_id"]))
    try:
        rows=conn.execute(
            """SELECT normalized_name,COALESCE(NULLIF(value_raw,''),value_preview,'') value
                 FROM identifier_observation_index WHERE exchange_id=? AND lower(normalized_name) LIKE '%owner%' ORDER BY id""",
            (int(exchange_id),),
        ).fetchall()
    except Exception:
        rows=[]
    matches=[]
    for row in rows:
        ids=aliases.get(_token(row["value"]),set())
        if len(ids)==1:
            iid=next(iter(ids)); matches.append((iid,str(row["normalized_name"]),str(row["value"])))
    unique={x[0] for x in matches}
    if len(unique)!=1: return None
    iid=next(iter(unique)); ident=conn.execute("SELECT name FROM identities WHERE id=?",(iid,)).fetchone()
    return {"identity_id":iid,"identity_name":str(ident["name"] if ident else f"Identity #{iid}"),"evidence":[{"field":f,"value":v} for _,f,v in matches]}


def maybe_emit_cross_owner_signal(conn, replay: dict[str, Any]) -> int | None:
    if str(replay.get("test_validity") or "") != "allowed" or not replay.get("replay_identity_id"):
        return None
    owner=observed_owner_identity(conn,int(replay["original_exchange_id"]))
    if not owner or int(owner["identity_id"])==int(replay["replay_identity_id"]):
        return None
    try:
        import negro_hunter as hunter
        ex=conn.execute("""SELECT e.operation_id,o.resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?""",(int(replay["original_exchange_id"]),)).fetchone()
        replay_name=replay.get("replay_identity_name") or (conn.execute("SELECT name FROM identities WHERE id=?",(int(replay["replay_identity_id"]),)).fetchone() or {"name":f"Identity #{replay['replay_identity_id']}"})["name"]
        hunter._upsert_signal_occurrence(
            conn, signal_key=f"replay_cross_owner:{int(replay['id'])}",kind="possible_cross_owner_access",severity="medium",
            title="Posible acceso cross-owner observado en Replay",
            message=f"Un Replay manual ejecutado como {replay_name} fue aceptado sobre evidencia cuyo owner observado apunta a {owner['identity_name']}. Revisa el impacto; 2xx no confirma por sí solo una vulnerabilidad.",
            source="builtin_rule:authorization_replay_cross_owner",resource_id=int(ex["resource_id"]) if ex else None,operation_id=int(ex["operation_id"]) if ex else None,
            exchange_id=int(replay["original_exchange_id"]),data={"authorization_replay_id":int(replay["id"]),"owner":owner,"replay_identity_id":int(replay["replay_identity_id"]),"replay_status":replay.get("response_status"),"rule_match":{"owner_differs":True,"behavior_allowed":True}},
        )
        row=conn.execute("SELECT id FROM signal_occurrences WHERE dedupe_key=?",(f"replay_cross_owner:{int(replay['id'])}:exchange:{int(replay['original_exchange_id'])}",)).fetchone()
        return int(row["id"]) if row else None
    except Exception:
        return None


def attach_to_hypothesis(conn, replay_id: int, hypothesis_id: int) -> None:
    replay=get_replay(conn,int(replay_id))
    if not replay: raise ValueError("Replay no encontrado")
    lead=conn.execute("SELECT evidence_json FROM leads_v2 WHERE id=?",(int(hypothesis_id),)).fetchone()
    if not lead: raise ValueError("Hipótesis no encontrada")
    try: ev=json.loads(lead["evidence_json"] or "[]")
    except Exception: ev=[]
    if not isinstance(ev,list): ev=[]
    if not any(isinstance(x,dict) and int(x.get("authorization_replay_id") or 0)==int(replay_id) for x in ev):
        ev.append({"source":"authorization_replay","authorization_replay_id":int(replay_id),"exchange_id":int(replay["original_exchange_id"]),"original_identity_id":replay.get("original_identity_id"),"replay_identity_id":replay.get("replay_identity_id"),"response_status":replay.get("response_status"),"test_validity":replay.get("test_validity")})
        conn.execute("UPDATE leads_v2 SET evidence_json=?,updated_at=? WHERE id=?",(json.dumps(ev,ensure_ascii=False),now_iso(),int(hypothesis_id)))
    conn.execute("UPDATE authorization_replays SET hypothesis_id=? WHERE id=?",(int(hypothesis_id),int(replay_id)))


def create_hypothesis_from_replay(conn, replay_id: int, *, title: str, why: str = "", next_test: str = "") -> int:
    import negro_hunter as hunter
    replay=get_replay(conn,int(replay_id))
    if not replay: raise ValueError("Replay no encontrado")
    hid=hunter.create_manual_hypothesis(conn,int(replay["original_exchange_id"]),title=title,why=why,next_test=next_test)
    attach_to_hypothesis(conn,int(replay_id),hid)
    if replay.get("test_validity") in {"state_invalid","inconclusive","transport_error"}:
        conn.execute("UPDATE leads_v2 SET status='candidate',result_notes=?,updated_at=? WHERE id=?",(
            "Replay no concluyente. Prepara un objeto fresco/estado válido y repite la prueba; no se interpreta como autorización protegida.",now_iso(),hid))
    return hid
