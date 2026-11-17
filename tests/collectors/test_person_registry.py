from core.collectors.person_registry import PersonRegistry
from core.models import OsintPerson


def P(name: str, **kw) -> OsintPerson:
    return OsintPerson(full_name=name, **kw)


def test_add_returns_true_then_false_for_duplicates():
    r = PersonRegistry()
    assert r.add(P("Alice Martin")) is True
    assert r.add(P("Alice Martin")) is False
    assert len(r.all) == 1


def test_key_is_case_whitespace_and_hyphen_insensitive():
    r = PersonRegistry()
    assert r.add(P("Marie-Ange Debon"))
    assert not r.add(P("  marie ange DEBON "))
    assert not r.add(P("MARIE-ANGE DEBON"))


def test_empty_names_are_rejected():
    r = PersonRegistry()
    assert r.add(P("")) is False
    assert r.add(P("   ")) is False
    assert r.all == []


def test_add_many_returns_only_new_and_keeps_first_seen():
    r = PersonRegistry()
    r.add(P("Alice Martin", role="CEO"))
    new = r.add_many([P("alice martin", role="other"), P("Bob Durand"), P("Bob Durand")])
    assert [p.full_name for p in new] == ["Bob Durand"]
    assert [p.role for p in r.all if p.full_name == "Alice Martin"] == ["CEO"]


def test_all_returns_a_copy():
    r = PersonRegistry()
    r.add(P("Alice Martin"))
    r.all.clear()
    assert len(r.all) == 1
