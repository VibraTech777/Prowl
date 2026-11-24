"""
core/collectors/person_registry.py — Visited-person registry for the person pivot.

Prevents the recursive pivot from searching the same person twice
(and therefore from looping forever).
"""

from __future__ import annotations

import re
import unicodedata

from core.models import OsintPerson

# Words that make an ALL-CAPS "name" a company, not a person (matched as whole words).
_LEGAL_ENTITY_WORDS = frozenset(
    {"SAS", "SARL", "SA", "SCI", "SCPA", "FIDUCIAIRE", "SOCIETE", "CABINET"}
)


def _fold(text: str) -> str:
    """Upper-case, accent-free copy ("Société" → "SOCIETE")."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).upper()


def is_pivot_candidate(name: str, role: str = "") -> bool:
    """
    False for entries that must never feed the person pivot:
      - external auditors ("Commissaire aux comptes titulaire / suppléant"): not staff;
      - a "name" that is really a company: written in capitals and containing a legal-form
        word (SAS, SARL, SA, SCI, SCPA, SOCIETE, FIDUCIAIRE, CABINET).
    They stay in the report as findings; they are just not investigated as people.
    """
    if "COMMISSAIRE AUX COMPTES" in _fold(role or ""):
        return False
    if name and name == name.upper() and name != name.lower():       # written in capitals
        if _LEGAL_ENTITY_WORDS & set(re.findall(r"[A-Z]+", _fold(name))):
            return False
    return True


class PersonRegistry:
    """Deduplicates persons across pivot levels."""

    def __init__(self):
        self._visited: set[str] = set()
        self._all: list[OsintPerson] = []

    @staticmethod
    def _key(name: str) -> str:
        return name.lower().strip().replace("-", " ")

    def knows(self, name: str) -> bool:
        """Has a person of this name already been registered?"""
        return self._key(name) in self._visited

    def add(self, person: OsintPerson) -> bool:
        """Register person. Returns True if new, False if duplicate."""
        key = self._key(person.full_name)
        if not key or key in self._visited:
            return False
        self._visited.add(key)
        self._all.append(person)
        return True

    def add_many(self, persons: list[OsintPerson]) -> list[OsintPerson]:
        """Add a batch, return only the new ones."""
        return [p for p in persons if self.add(p)]

    @property
    def all(self) -> list[OsintPerson]:
        return list(self._all)
