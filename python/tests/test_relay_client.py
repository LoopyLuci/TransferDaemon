"""The relay client's forwards against a stand-in relay: pipelined, and reusing one challenge.

The stand-in is what makes these exact. It holds its acknowledgements until it has the forwards it wants, which a
client that waited for each ack before sending the next would never reach. The reference relay is covered by
`test_relay_hub.py` and `test_relay_interop.py`.
"""

import asyncio
import time

from transferd import relay as R
from transferd.relay_client import RelayClient


class StandIn(asyncio.DatagramProtocol):
    """Answers challenge requests, and acknowledges forwards once `acks_after` of them have arrived, all at once."""

    def __init__(self, acks_after: int, difficulty: int) -> None:
        self.acks_after = acks_after
        self.difficulty = difficulty
        self.challenges = 0
        self.forwards: list = []
        self._pending: list = []
        self.transport = None

    def connection_made(self, transport) -> None:  # noqa: ANN001 - asyncio's signature
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001 - asyncio's signature
        if data[0] == R.Tag.CHALLENGE:
            self.challenges += 1
            expires_at = int(time.time()) + 60
            self.transport.sendto(R.encode_challenge(bytes([1]) * 16, expires_at, self.difficulty), addr)
        elif data[0] == R.Tag.FORWARD:
            # The forward's sequence number follows its tag, the 32-byte token and the 8-byte proof of work.
            seq = int.from_bytes(data[1 + 32 + 8 : 1 + 32 + 8 + 2], "little")
            self.forwards.append(seq)
            self._pending.append((seq, addr))
            if len(self._pending) == self.acks_after:
                for pending_seq, to in self._pending:
                    self.transport.sendto(R.encode_ack(pending_seq), to)
                self._pending.clear()


async def _stand_in(acks_after: int, difficulty: int):
    loop = asyncio.get_running_loop()
    protocol = StandIn(acks_after, difficulty)
    transport, _ = await loop.create_datagram_endpoint(lambda: protocol, local_addr=("127.0.0.1", 0))
    return protocol, transport, transport.get_extra_info("sockname")[1]


def test_forwards_are_pipelined_five_are_in_flight_before_the_first_is_acknowledged():
    async def main() -> None:
        protocol, transport, port = await _stand_in(acks_after=5, difficulty=0)
        client = RelayClient(("127.0.0.1", port), timeout=5.0)
        await client.open()
        try:
            token = bytes([9]) * 32
            sends = [client.forward(token, bytes([i])) for i in range(5)]
            # The stand-in acknowledges none until all five have arrived, so a client that waited for each ack would
            # stall here.
            await asyncio.wait_for(asyncio.gather(*sends), 3.0)
            assert len(set(protocol.forwards)) == 5, "each forward carries its own sequence number"
            assert protocol.challenges == 1, "one challenge serves all five forwards"
        finally:
            client.close()
            transport.close()

    asyncio.run(asyncio.wait_for(main(), 20))


def test_a_forward_reuses_the_relay_challenge_rather_than_fetching_one():
    async def main() -> None:
        protocol, transport, port = await _stand_in(acks_after=1, difficulty=8)
        client = RelayClient(("127.0.0.1", port), timeout=5.0)
        await client.open()
        try:
            token = bytes([4]) * 32
            for i in range(4):
                await asyncio.wait_for(client.forward(token, bytes([i])), 3.0)
            assert len(protocol.forwards) == 4, "every forward reached the relay"
            assert protocol.challenges == 1, "the challenge is fetched once, not once per forward"
        finally:
            client.close()
            transport.close()

    asyncio.run(asyncio.wait_for(main(), 20))
