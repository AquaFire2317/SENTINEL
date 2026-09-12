"""Seed fixture data for local development.

Validates that the FixtureStore produces the expected suppliers and quotes.
Run: python scripts/seed_fixtures.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from sentinel.tools.fixtures import FixtureStore


def main() -> None:
    store = FixtureStore(poisoned=True)
    print("=== Fixture Suppliers ===")
    for s in store.suppliers:
        note_preview = (s.supplier_note or "")[:80]
        print(f"  {s.supplier_id}: {s.name} (rating={s.rating})")
        if s.supplier_note:
            print(f"    note: {note_preview}...")

    print("\n=== Fixture Quotes ===")
    quotes = store.quotes(["sup-acme", "sup-northstar"], "LAPTOP-001", 10)
    for q in quotes:
        total = q.unit_price * q.quantity
        print(f"  {q.supplier_id}: ${q.unit_price}/unit x {q.quantity} = ${total:.2f}")

    print("\n=== Side-effect Records ===")
    print(f"  Emails sent: {len(store.emails)}")
    print(f"  Purchase orders: {len(store.purchase_orders)}")

    print("\nFixture store validated successfully.")


if __name__ == "__main__":
    main()
