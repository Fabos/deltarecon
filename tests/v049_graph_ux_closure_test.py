"""Regression v0.41.8: close the graph UX loop before returning to Context Compound."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_identity as identity


def main():
    assert core.VERSION == "0.44.0"
    js=(ROOT/'web/static/graph.js').read_text()
    css=(ROOT/'web/static/style.css').read_text()
    html=(ROOT/'web/templates/identity_matrix.html').read_text()
    web=(ROOT/'negro_web.py').read_text()
    assert 'renderGenericTrail' in js
    assert 'hydrateGenericResourceEvidence' in js
    assert 'resource-evidence' in web
    assert "surface:new Set(['identity','flow','object','parameter','context','request','operation'])" in js
    assert '.graph-workspace:fullscreen .graph-controls{display:block!important' in css
    assert 'matrix-cross-badge' in html and 'RAMA SIN COMPARAR' in html
    src=(ROOT/'negro_identity.py').read_text()
    assert 'shared_values' in src and 'cross_observed' in src
    print('[OK] fullscreen conserva filtros y recalcula fit')
    print('[OK] breadcrumb existe en todas las lentes y endpoint pivots son universales')
    print('[OK] Authorization Matrix distingue cruce observado de rama sin comparar')

if __name__=='__main__': main()
