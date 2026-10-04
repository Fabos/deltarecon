#!/usr/bin/env python3
"""Regression: separated Hypothesis/Investigation UX; labs stay outside Negro core."""
from pathlib import Path
import base64
import importlib.util
import os
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
from negro_web import _hypothesis_rows, _investigation_rows


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def capture(paths, domain):
    req=("GET /login HTTP/1.1\r\nHost: app.local\r\n\r\n").encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nOK").encode()
    return core.upsert_http_observation(paths,domain,url="https://app.local/login",method="GET",source="burp_proxy",status_code=200,authenticated=False,tool="PROXY",request_b64=b64(req),response_b64=b64(resp))


def main():
    assert core.VERSION == "0.41.6"
    with tempfile.TemporaryDirectory(prefix="negro-ux-lab-") as td:
        paths=core.ensure_workspace(Path(td)/"workspace","app.local")
        ex=capture(paths,"app.local")
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(ex["exchange_id"]),"app.local",emit_notifications=False)
            hid=hunter.create_manual_hypothesis(conn,int(ex["exchange_id"]),title="¿Login cambia por sesión?",why="UX",next_test="Comparar")
            inv1=hunter.create_investigation(conn,title="Prueba A")
            inv2=hunter.create_investigation(conn,title="Prueba B")
            hunter.link_investigation_entity(conn,inv1,"hypothesis",hid,"pursuing")
        rows=_hypothesis_rows(paths)
        row=next(x for x in rows if int(x["id"])==hid)
        assert [int(x["id"]) for x in row["investigations"]] == [inv1]
        assert inv2 in [int(x["id"]) for x in row["available_investigations"]]
        assert inv1 not in [int(x["id"]) for x in row["available_investigations"]]
        assert len(_investigation_rows(paths)) == 2

        # Manual hypotheses can also be legitimate origins for a new Investigation.
        with core.db_connect(paths) as conn:
            hid2=hunter.create_manual_hypothesis(conn,int(ex["exchange_id"]),title="¿Otra rama?",why="manual",next_test="probar")
            created=hunter.promote_ai_hypothesis_to_investigation(conn,hid2)
            assert int(created["source_hypothesis_id"]) == hid2
            link=conn.execute("SELECT 1 FROM investigation_links WHERE investigation_id=? AND entity_type='hypothesis' AND entity_id=?",(int(created["id"]),hid2)).fetchone()
            assert link

    base=(ROOT/'web/templates/base.html').read_text()
    hyp=(ROOT/'web/templates/hypotheses.html').read_text()
    inv=(ROOT/'web/templates/investigations.html').read_text()
    web=(ROOT/'negro_web.py').read_text()
    assert '>Hipótesis</a>' in base and '>Investigaciones</a>' in base
    assert 'Convertir en Investigación' not in hyp
    assert 'Adjuntar a Investigación' in hyp
    assert 'INVESTIGACIONES · WORKSPACES' in inv
    assert '@app.get("/t/{target_key}/investigations"' in web
    assert '@app.post("/t/{target_key}/hypothesis/{lead_id}/investigation")' in web

    # Labs are external benchmark artifacts and must never ship inside Negro core.
    assert not (ROOT/'labs').exists()
    assert not any(ROOT.glob('LAB_*'))

    print('[OK] Hipótesis e Investigaciones tienen navegación separada')
    print('[OK] una Hypothesis muestra asociaciones many-to-many y permite adjuntar otra Investigation')
    print('[OK] una Hypothesis manual puede originar una Investigation sin usar un flujo AI-only')
    print('[OK] Negro core no incluye labs; los benchmarks se distribuyen por separado')


if __name__ == '__main__':
    main()
