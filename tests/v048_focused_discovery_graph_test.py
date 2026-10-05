#!/usr/bin/env python3
"""Regression v0.41.8: Discovery defaults to pivot→endpoints and layers are explicit."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core


def main():
    assert core.VERSION=='0.42.0'
    html=(ROOT/'web/templates/graph.html').read_text()
    js=(ROOT/'web/static/graph.js').read_text()
    css=(ROOT/'web/static/style.css').read_text()

    # Focused default: endpoint map first, context only on demand.
    assert "discovery:{operation:false,flow:false,object:false,request:false,identity:false,parameter:false,context:false}" in js
    for layer in ('identity','flow','object','parameter','context','request'):
        assert f'data-layer-wrap="{layer}"' in html, layer
    assert 'Sólo cruces / no observados' in html
    assert 'discoveryResourceHasCross' in js

    # Breadcrumb remains visible; insights are an opt-in drawer, not permanent canvas tax.
    assert 'data-graph-discovery-trail' in html
    assert 'data-discovery-insights-toggle' in html
    assert 'discoveryInsightsOpen' in js
    assert '.graph-discovery-insights{position:absolute' in css

    # Endpoint detail is a navigation surface: real Requests + explicit key/value pivots.
    assert 'Requests que justifican la relación' in js
    assert 'Seguir key' in js and 'Seguir valor' in js
    assert 'Authorization Mix observado' in js
    assert '↔ CRUCE · ' in js and '○ no observado' in js
    assert 'no observado' in js

    # Discovery identity layer reuses compare cards instead of spraying tiny nodes.
    assert "preset==='discovery'&&layerEnabled('identity')" in js
    assert 'autoLayoutDiscovery' in js
    assert 'discovery-owner-card' in js

    # Endpoint memory badges must survive the redesign.
    assert '◆H${intel.hypothesisCount}' in js
    assert '↔C${intel.correlationCount}' in js
    assert '⚡S${intel.localSignalCount}' in js

    # Fullscreen must target the workspace only, leaving page chrome out.
    assert 'graphWorkspace.requestFullscreen()' in js
    assert '.graph-workspace:fullscreen' in css

    # Lab policy: core package has no bundled labs.
    assert not (ROOT/'labs').exists()
    assert not any(ROOT.glob('LAB_*'))

    print('[OK] Discovery abre limpio en pivote → endpoints y agrega contexto sólo bajo demanda')
    print('[OK] Identity layer reutiliza Authorization Mix con owner/no-observado')
    print('[OK] Endpoint panel permite Request → key → valor → nuevo pivote')
    print('[OK] H/C/S permanecen visibles sobre endpoints')
    print('[OK] Fullscreen usa sólo el workspace del grafo')
    print('[OK] Negro core permanece libre de labs')

if __name__=='__main__':
    main()
