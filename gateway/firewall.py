from __future__ import annotations

import asyncio
import contextlib
import logging

from .protocol import FIREWALL_PROBE_REPLY

LOGGER = logging.getLogger(__name__)

async def _handle_firewall_probe(reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> None:
    """Firewall probe listener (default port 2021).

    Homeworld 1 probes this port with TCP SYN to detect NAT/firewall mode.
    It retries ~4 times at ~0.5 s intervals.  Simply accepting the connection
    is sufficient — no data exchange is required.
    """
    peer = writer.get_extra_info("peername", ("?", 0))
    LOGGER.debug("Firewall probe accepted from %s:%s", *peer)
    with contextlib.suppress(Exception):
        writer.write(FIREWALL_PROBE_REPLY)
        await writer.drain()
    writer.close()
    await writer.wait_closed()


