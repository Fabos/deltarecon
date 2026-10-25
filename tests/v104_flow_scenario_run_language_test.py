#!/usr/bin/env python3
"""Regression for v0.104: Flow -> Scenario -> Run mental model, Runner internal only."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = Environment(loader=FileSystemLoader(str(ROOT / 'web' / 'templates')))
    for name in ('flow_detail.html','runners.html','runner_detail.html','flow_run_detail.html','resource.html','replay_prepare.html'):
        env.get_template(name)

    flow = (ROOT/'web/templates/flow_detail.html').read_text()
    scenarios = (ROOT/'web/templates/runners.html').read_text()
    scenario = (ROOT/'web/templates/runner_detail.html').read_text()
    flow_run = (ROOT/'web/templates/flow_run_detail.html').read_text()
    resource = (ROOT/'web/templates/resource.html').read_text()
    replay = (ROOT/'web/templates/replay_prepare.html').read_text()
    web = (ROOT/'negro_web.py').read_text()

    assert '▶ Reproducir flujo' in flow
    assert '+ Crear prueba' in flow
    assert 'Crear prueba (Escenario)' in flow
    assert '▶ Ejecutar Flow' not in flow
    assert '<b>Flow</b><small>lo que ocurrió</small>' in flow
    assert '<b>Escenario</b><small>lo que quiero probar</small>' in flow
    assert '<b>Run</b><small>qué ocurrió al ejecutar</small>' in flow

    assert '<b>Escenario</b><small>lo que quiero probar</small>' in scenarios
    assert '<b>Run</b><small>resultado de una ejecución</small>' in scenarios
    assert '▶ Ejecutar prueba' in scenario
    assert 'Qué hará esta prueba' in scenario
    assert 'REPRODUCCIÓN · RUN #' in flow_run

    assert '<summary>▶ Crear prueba</summary>' in resource
    assert '<summary>▶ Runner</summary>' not in resource
    assert 'Crear prueba desde Flow' in replay
    assert 'Preparar con Runner' not in replay

    # Compatibility: implementation and routes remain runner-based internally.
    assert '@app.get("/t/{target_key}/runners"' in web
    assert '@app.post("/t/{target_key}/runners/{runner_id}/execute"' in web

    print('[OK] Flow is presented as observed process and uses Reproducir flujo')
    print('[OK] Scenario is presented as the reusable test and uses Ejecutar prueba')
    print('[OK] Run is presented as execution evidence/result')
    print('[OK] Runner remains an internal compatibility concept, not a primary Request action')


if __name__ == '__main__':
    main()
