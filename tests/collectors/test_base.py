import inspect

import pytest

from core.collectors.base import BaseCollector
from core.models import CollectorResult


class _Free(BaseCollector):
    name = "free"

    async def collect(self, target):
        return CollectorResult(findings=[])


class _Keyed(BaseCollector):
    name = "keyed"
    requires_api_key = True
    api_key_env = "PROWL_TEST_KEY"

    async def collect(self, target):
        return CollectorResult(findings=[])


def test_base_collector_is_abstract():
    assert inspect.isabstract(BaseCollector)
    with pytest.raises(TypeError):
        BaseCollector()


def test_default_flags():
    c = _Free()
    assert c.french_only is False
    assert c.requires_crawl is False
    assert c.tier == 1


def test_free_collector_always_available():
    assert _Free().is_available() is True


def test_keyed_collector_availability(monkeypatch):
    monkeypatch.delenv("PROWL_TEST_KEY", raising=False)
    assert _Keyed().is_available() is False
    monkeypatch.setenv("PROWL_TEST_KEY", "   ")
    assert _Keyed().is_available() is False
    monkeypatch.setenv("PROWL_TEST_KEY", "secret")
    assert _Keyed().is_available() is True


def test_repr_mentions_availability(monkeypatch):
    monkeypatch.delenv("PROWL_TEST_KEY", raising=False)
    assert "unavailable" in repr(_Keyed())
    assert "available" in repr(_Free())


def test_person_collector_is_abstract_with_defaults(monkeypatch):
    from core.collectors.base import BasePersonCollector

    assert inspect.isabstract(BasePersonCollector)
    with pytest.raises(TypeError):
        BasePersonCollector()

    class _P(BasePersonCollector):
        name = "p"
        requires_api_key = True
        api_key_env = "PROWL_TEST_PKEY"

        async def collect_person(self, person, target):
            return CollectorResult(findings=[])

    p = _P()
    assert (p.tier, p.request_delay) == (2, 1.5)
    monkeypatch.delenv("PROWL_TEST_PKEY", raising=False)
    assert p.is_available() is False
    monkeypatch.setenv("PROWL_TEST_PKEY", "k")
    assert p.is_available() is True
