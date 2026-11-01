from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
class SemanticWorkbenchSourceTest(unittest.TestCase):
    def test_pretty_is_default(self):
        tpl=(ROOT/'web/templates/http_workbench.html').read_text();js=(ROOT/'web/static/app.js').read_text()
        self.assertIn('class="active" data-view-mode="request" data-mode="pretty"', tpl)
        self.assertIn('class="active" data-view-mode="response" data-mode="pretty"', tpl)
        self.assertIn("const mode={request:'pretty',response:'pretty'}", js)
    def test_existing_learned_annotations_are_reused(self):
        py=(ROOT/'negro_workbench.py').read_text();js=(ROOT/'web/static/app.js').read_text()
        self.assertIn('http_inspector.learned_annotations(conn, int(exchange_id))', py)
        self.assertIn('"annotations": safe_annotations', py)
        for cls in ('http-ann-auth','http-ann-resolver','http-ann-context','http-ann-entity'): self.assertIn(cls, js)
    def test_http_density_is_tighter(self):
        css=(ROOT/'web/static/style.css').read_text();self.assertIn('font:10.5px/1.4 "JetBrains Mono"', css)
if __name__ == '__main__': unittest.main()
