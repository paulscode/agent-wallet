# SPDX-License-Identifier: MIT
"""Read-only catalog endpoint surfacing the bundled small-channel peer
list to API-key callers (and, via a session-authed wrapper in
``app/dashboard/api.py``, to the dashboard SPA).

The endpoint always returns 200; downstream consumers handle the
``enabled: false`` and empty-list cases gracefully. The body shape:

```json
{
  "enabled": true,
  "snapshot_date": "2026-06-27",
  "network": "bitcoin",
  "peers": [ {<SmallChannelPeer projected to JSON>}, ... ]
}
```

``enabled: false`` ⇔ operator set
``SMALL_CHANNEL_PEER_CATALOG_ENABLED=false`` ⇒ ``peers`` is empty.
``network`` mirrors ``settings.bitcoin_network`` so a caller doesn't
have to look it up separately.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends

from app.core.config import API_V1_PREFIX, settings
from app.core.security import get_api_key
from app.models.api_key import APIKey
from app.services.small_channel_peers import SNAPSHOT_DATE, all_peers

router = APIRouter(prefix=f"{API_V1_PREFIX}/peer-catalog", tags=["peer-catalog"])


def _peer_to_dict(peer: Any) -> dict[str, Any]:
    """Project a :class:`SmallChannelPeer` dataclass to a plain JSON dict.

    ``dataclasses.asdict`` recursively converts nested dataclasses, but
    it leaves tuples as lists in JSON — fine for the API surface. The
    ``caveats`` list keeps its ``{kind, detail}`` shape.
    """
    return asdict(peer)


@router.get("/small-channel")
async def get_small_channel_catalog(
    api_key: APIKey = Depends(get_api_key),
) -> dict[str, Any]:
    """Return the small-channel peer catalog filtered to the configured
    Bitcoin network.

    Any valid API key can read the catalog — the data isn't sensitive
    (it ships in-repo and in `docs/small-channel-peers.md`), and the
    dashboard wrapper needs to read it without an admin key."""
    network = settings.bitcoin_network
    peers = all_peers(network=network) if settings.small_channel_peer_catalog_enabled else ()
    return {
        "enabled": bool(settings.small_channel_peer_catalog_enabled),
        "snapshot_date": SNAPSHOT_DATE,
        "network": network,
        "peers": [_peer_to_dict(p) for p in peers],
    }


__all__ = ["router"]
