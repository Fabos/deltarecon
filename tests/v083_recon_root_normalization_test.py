from pathlib import Path
import tempfile
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core


def test_www_seed_normalizes_to_parent_recon_root():
    assert core.normalize_recon_root('www.viveterpel.com') == 'viveterpel.com'
    assert core.normalize_recon_root('https://www.example.com/path') == 'example.com'


def test_non_www_subdomain_is_not_silently_promoted():
    assert core.normalize_recon_root('api.example.com') == 'api.example.com'
    assert core.normalize_recon_root('qa.example.com') == 'qa.example.com'


def test_existing_www_recon_root_self_heals_when_target_is_read(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setattr(core, 'TARGETS_PATH', Path(td) / 'targets.json')
        monkeypatch.setattr(core, 'CONFIG_PATH', Path(td) / 'config.json')
        key = core.register_target(
            'example.com', Path(td) / 'ws',
            scopes=['example.com', 'www.viveterpel.com'],
            recon_roots=['www.viveterpel.com'],
        )
        target = core.get_target(key)
        assert target['recon_roots'] == ['example.com', 'viveterpel.com']
