#!/usr/bin/env python3
"""Regression: manual Hypotheses can save notes/decisions and expose demonstrated/refuted UX."""
from pathlib import Path
import base64, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter

def b64(x:bytes)->str:
    return base64.b64encode(x).decode()

def main():
    assert core.VERSION == "0.43.0"
    with tempfile.TemporaryDirectory(prefix="negro-v044-") as td:
        paths=core.ensure_workspace(Path(td)/"workspace","shop.negro.lab")
        req=b"POST /api/refunds HTTP/1.1\r\nHost: shop.negro.lab\r\nContent-Length: 2\r\n\r\n{}"
        resp=b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"field\":\"returnId\"}"
        ex=core.upsert_http_observation(paths,"shop.negro.lab",url="http://shop.negro.lab/api/refunds",method="POST",source="burp_proxy",status_code=400,authenticated=True,tool="PROXY",request_b64=b64(req),response_b64=b64(resp))
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(ex["exchange_id"]),"shop.negro.lab",emit_notifications=False)
            hid=hunter.create_manual_hypothesis(conn,int(ex["exchange_id"]),title="¿Puede B hacer refund?",why="manual",next_test="probar")
        out=core.update_hypothesis(paths,hid,status="confirmed",result_notes="Refund cross-account demostrado")
        assert out["status"]=="confirmed"
        assert out["result_notes"]=="Refund cross-account demostrado"
        with core.db_connect(paths) as conn:
            row=conn.execute("SELECT source,status,result_notes FROM leads_v2 WHERE id=?",(hid,)).fetchone()
            assert str(row["source"]).upper()=="MANUAL"
            assert row["status"]=="confirmed"
            assert row["result_notes"]=="Refund cross-account demostrado"
    tpl=(ROOT/'web/templates/hypotheses.html').read_text()
    assert '>Demostrada</option>' in tpl
    assert '>Refutada</option>' in tpl
    print('[OK] Hypothesis manual guarda nota y estado Demostrada')
    print('[OK] UI expone Demostrada y Refutada sin depender de source=AI')

if __name__=='__main__': main()
