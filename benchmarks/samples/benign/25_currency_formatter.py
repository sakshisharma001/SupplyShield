"""Currency and number formatting."""
from decimal import Decimal, ROUND_HALF_UP

def format_usd(amount: float) -> str:
    d = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"${d:,.2f}"
