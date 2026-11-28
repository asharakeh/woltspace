"""Disposable connector: real send handler with a file-backed Telegram stand-in."""
import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import connector_client
import telegram_real


class Bot:
    async def send_message(self, chat_id, text):
        assert (chat_id, text) == ("42", "Woltspace broker notice.")
        with Path("/fixture/accepts").open("ab", buffering=0) as ledger:
            ledger.write(b"accepted\n")
            os.fsync(ledger.fileno())
        await asyncio.Event().wait()  # crash before the response reaches the registry


telegram_real.APP = SimpleNamespace(bot=Bot())
asyncio.run(connector_client.Client("telegram", on_send=telegram_real.on_send).run_forever())
