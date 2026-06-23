from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import kup.__main__ as kup_main
from kup.hello import hello
from kup.nix import ARCH
from kup.package import InstalledVersion, read_generation_manifests

if TYPE_CHECKING:
    from pathlib import Path

    from pytest import MonkeyPatch

SHA_A = 'a' * 40
SHA_B = 'b' * 40


def test_hello() -> None:
    assert hello('World') == 'Hello, World!'


def _write_generation(gens_dir: Path, generation: int, elements: object) -> None:
    link = gens_dir / f'profile-{generation}-link'
    link.mkdir()
    (link / 'manifest.json').write_text(json.dumps({'version': 3, 'elements': elements}))


def _kontrol_element(sha: str) -> dict:
    return {
        'active': True,
        'attrPath': f'packages.{ARCH}.kontrol',
        'storePaths': [f'/nix/store/{sha[:8]}-kontrol'],
        'url': f'github:runtimeverification/kontrol/{sha}',
    }


def test_read_generation_manifests_sorts_and_skips_gc(tmp_path: Path) -> None:
    gens_dir = tmp_path / 'profiles'
    gens_dir.mkdir()
    _write_generation(gens_dir, 3, [_kontrol_element(SHA_B)])
    _write_generation(gens_dir, 1, [_kontrol_element(SHA_A)])
    # a garbage-collected generation: link exists but manifest is gone
    (gens_dir / 'profile-2-link').mkdir()
    # an unrelated symlink that must be ignored
    (gens_dir / 'profile').symlink_to('profile-3-link')

    generations = read_generation_manifests(str(gens_dir))

    assert [g[0] for g in generations] == [1, 3]
    assert all(isinstance(elements, dict) for _, _, elements in generations)
    first_element = next(iter(generations[0][2].values()))
    assert first_element['url'] == f'github:runtimeverification/kontrol/{SHA_A}'


def test_read_generation_manifests_normalizes_uri(tmp_path: Path) -> None:
    gens_dir = tmp_path / 'profiles'
    gens_dir.mkdir()
    _write_generation(
        gens_dir,
        1,
        [
            {
                'attrPath': f'packages.{ARCH}.kontrol',
                'storePaths': ['/nix/store/x-kontrol'],
                'uri': f'github:runtimeverification/kontrol/{SHA_A}',
                'originalUri': 'git+file:///home/me/kontrol',
            }
        ],
    )

    [(_, _, elements)] = read_generation_manifests(str(gens_dir))
    element = next(iter(elements.values()))
    assert element['url'] == f'github:runtimeverification/kontrol/{SHA_A}'
    assert element['originalUrl'] == 'git+file:///home/me/kontrol'


def test_read_generation_manifests_missing_dir(tmp_path: Path) -> None:
    assert read_generation_manifests(str(tmp_path / 'does-not-exist')) == []


def test_build_history_collapses_and_marks_current(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    gens_dir = tmp_path / 'profiles'
    gens_dir.mkdir()
    _write_generation(gens_dir, 1, [_kontrol_element(SHA_A)])
    _write_generation(gens_dir, 2, [_kontrol_element(SHA_A)])  # unchanged -> collapsed
    _write_generation(gens_dir, 3, [_kontrol_element(SHA_B)])

    monkeypatch.setattr(kup_main, 'profile_generations_dir', lambda: (str(gens_dir), 3))
    monkeypatch.setattr(kup_main, '_enrich_tags', lambda history: history)

    history = kup_main.build_history(None)

    versions = history['kontrol']
    assert [(v.generation, v.commit, v.is_current) for v in versions] == [
        (1, SHA_A, False),
        (3, SHA_B, True),
    ]


def test_build_history_local_checkout_and_filter(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    gens_dir = tmp_path / 'profiles'
    gens_dir.mkdir()
    _write_generation(
        gens_dir,
        1,
        [
            _kontrol_element(SHA_A),
            {
                'attrPath': f'packages.{ARCH}.kevm',
                'storePaths': ['/nix/store/y-kevm'],
                'originalUrl': 'git+file:///home/me/evm-semantics/master',
            },
        ],
    )

    monkeypatch.setattr(kup_main, 'profile_generations_dir', lambda: (str(gens_dir), 1))
    monkeypatch.setattr(kup_main, '_enrich_tags', lambda history: history)

    history = kup_main.build_history('kevm')

    assert set(history.keys()) == {'kevm'}
    [version] = history['kevm']
    assert version.commit is None
    assert version.local_path == '/home/me/evm-semantics/master'
    assert version.is_current is True


def test_build_history_no_profile(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(kup_main, 'profile_generations_dir', lambda: None)
    assert kup_main.build_history(None) == {}


def test_format_version_renders_tag_commit_and_local() -> None:
    tagged = InstalledVersion(1, '2026-01-01', SHA_A, 'v1.0.1', None, is_current=True)
    untagged = InstalledVersion(2, '2026-01-02', SHA_B, None, None, is_current=False)
    local = InstalledVersion(3, '2026-01-03', None, None, '/home/me/kontrol', is_current=False)

    assert kup_main._format_version(tagged) == f'{SHA_A[:7]} (v1.0.1)'
    assert kup_main._format_version(untagged) == SHA_B[:7]
    assert kup_main._format_version(local) == 'local checkout (/home/me/kontrol)'


def test_profile_generations_dir_resolves_symlink(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    profiles = tmp_path / 'state' / 'nix' / 'profiles'
    profiles.mkdir(parents=True)
    (profiles / 'profile-7-link').mkdir()
    (profiles / 'profile').symlink_to('profile-7-link')
    home = tmp_path / 'home'
    home.mkdir()
    (home / '.nix-profile').symlink_to(profiles / 'profile')

    monkeypatch.setattr(os, 'getenv', lambda key, default=None: str(home) if key == 'HOME' else default)

    assert kup_main.profile_generations_dir() == (str(profiles), 7)
