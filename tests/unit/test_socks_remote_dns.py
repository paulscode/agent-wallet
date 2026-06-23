# SPDX-License-Identifier: MIT
"""Pin that the SOCKS5 stack resolves hostnames REMOTELY (no DNS leak).

The anonymize egress uses ``socks5://`` proxy URLs. With the pinned
httpx/socksio stack a SOCKS5 CONNECT to a hostname is encoded with
``ATYP=DOMAINNAME``, i.e. the proxy (Tor) resolves the name — the client
never does a local DNS lookup. This test fails loudly if a dependency
bump ever changes that to local resolution (which would leak DNS for
every anonymize / Tor egress).
"""

from socksio import socks5


def test_socks5_connect_to_hostname_uses_domain_name_atyp():
    req = socks5.SOCKS5CommandRequest.from_address(
        socks5.SOCKS5Command.CONNECT,
        ("example.onion", 443),
    )
    assert req.atype == socks5.SOCKS5AType.DOMAIN_NAME


def test_socks5_connect_to_ipv4_uses_ipv4_atyp():
    # Sanity: a literal IP is sent as IPV4 (not domain), proving the
    # DOMAIN_NAME result above is specifically the hostname path.
    req = socks5.SOCKS5CommandRequest.from_address(
        socks5.SOCKS5Command.CONNECT,
        ("127.0.0.1", 443),
    )
    assert req.atype == socks5.SOCKS5AType.IPV4_ADDRESS
