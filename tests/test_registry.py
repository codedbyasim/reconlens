"""Entry points and the fallback loader."""

from __future__ import annotations

from importlib.metadata import entry_points

import pytest

from reconlens.plugins._template import ExampleSource
from reconlens.plugins.base import Source
from reconlens.plugins.registry import BUILTIN_PATHS, load_sources
from reconlens.plugins.registry import _iter_entry_points as iter_entry_points


def test_installed_entry_points_match_the_builtin_list() -> None:
    installed = {(item.name, item.value) for item in entry_points(group="reconlens.sources")}
    assert installed == set(BUILTIN_PATHS)


def test_every_builtin_loads_and_the_template_is_not_registered() -> None:
    sources, errors = load_sources()
    assert errors == []
    names = {source.name for source in sources}
    assert {name for name, _path in BUILTIN_PATHS} == names
    assert ExampleSource.name not in names
    assert all(isinstance(source, Source) for source in sources)
    assert all(source.description.strip() for source in sources)
    assert all(source.target_types for source in sources)


def test_a_broken_plugin_does_not_drop_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "reconlens.plugins.registry._iter_entry_points",
        lambda: [
            ("dns", "reconlens.plugins.dns_records:DnsSource"),
            ("broken", "reconlens.plugins.does_not_exist:Nope"),
        ],
    )
    sources, errors = load_sources()
    assert [source.name for source in sources] == ["dns"]
    assert errors[0].name == "broken"
    assert iter_entry_points  # the helper stays importable for this assertion's monkeypatch target
