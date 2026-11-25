"""A TCP link keeps every frame it receives, even when its reader falls behind.

Mirrors `typescript/test/tcp_route.test.ts`. While the inbox is full the link stops reading its socket, so the frames
wait in TCP and the sender is held back. The earlier code dropped the frames that arrived while the inbox was full.
"""

import asyncio
import os

from transferd.frames import PING, VERSION_CURRENT, Frame
from transferd.link import RECV_QUEUE, TcpLink
from transferd.tunnel import derive_link_keys


def test_a_full_inbox_holds_the_sender_back_instead_of_dropping_frames():
    async def main():
        keys = derive_link_keys(os.urandom(32))
        accepted: asyncio.Queue = asyncio.Queue()

        async def on_connect(reader, writer):
            await accepted.put((reader, writer))

        server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
        server_reader, server_writer = await asyncio.wait_for(accepted.get(), 5)
        sender = TcpLink(client_reader, client_writer, keys)
        receiver = TcpLink(server_reader, server_writer, keys.swapped())
        sender.start()
        receiver.start()

        # More frames than the inbox holds. They are small, so the sender produces them well within the reader's pause.
        total = RECV_QUEUE + 300
        body = bytes(256)
        stop = False

        async def produce():
            for seq in range(total):
                frame = Frame(VERSION_CURRENT, PING, 0, seq, body)
                while not sender.send(frame):
                    if stop:
                        return
                    await asyncio.sleep(0.001)

        async def consume() -> list:
            # The reader waits first, so the inbox fills before anything is taken from it.
            await asyncio.sleep(1.0)
            seqs = []
            while len(seqs) < total:
                frame = receiver.try_recv()
                if frame is None:
                    await asyncio.sleep(0.001)
                else:
                    seqs.append(frame.seq)
            return seqs

        try:
            _, seqs = await asyncio.wait_for(asyncio.gather(produce(), consume()), 30)
            assert len(seqs) == total, "no frame is dropped"
            assert seqs == list(range(total)), "the frames arrive in order"
        finally:
            stop = True
            sender.close()
            receiver.close()
            server.close()

    asyncio.run(main())
