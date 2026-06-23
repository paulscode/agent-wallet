# SPDX-License-Identifier: MIT
"""Shared BOLT11 invoice fixtures for tests.

``BIND_INVOICE`` is a real BOLT11 invoice; ``BIND_PAYMENT_HASH`` is its
decoded payment hash. Reverse-swap creation now requires the returned
invoice's payment hash to equal the wallet's preimage hash (security
C1), so tests that mock a Boltz reverse response must return this
invoice and patch the preimage hash to match.
"""

BIND_INVOICE = (
    "lnbc1019200n1p4q72m5pp5zh8f3dksgym27cgxjav2fx4zgljlvtd8r95g5lfj7nke2t08y5d"
    "sdql2djkuepqw3hjqsj5gvsxzerywfjhxuccqzylxqyp2xqsp58cj6lrx0qdgd8fwf4552gmj"
    "9wrvxdwd0jd54krq0lttxlxempg8q9qxpqysgqmf3leftwxdyu77fswnuktm5z4px3esh2kxq"
    "v2j8255k32p9r5tvrznud0acqf53pwpmgdrq8vlufeydv9gnd8v27e9exze0m0gtrpyspr8j5xh"
)
BIND_PAYMENT_HASH = "15ce98b6d04136af61069758a49aa247e5f62da719688a7d32f4ed952de7251b"

# The invoice's HRP encodes 1019200n BTC = 101_920 sats. Reverse-swap
# creation requires the returned hold invoice's principal to equal the
# requested send amount, so tests that mock a Boltz reverse response and
# return this invoice must request exactly this amount.
BIND_INVOICE_PRINCIPAL_SATS = 101_920
