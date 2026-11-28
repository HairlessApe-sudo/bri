"""One-shot response faults outside real protected ASGI handlers; local signed fixture only."""
import asyncio
from contextlib import contextmanager
from hashlib import sha256
import json
from threading import Event, Lock
from unittest.mock import patch
from uuid import UUID

from a13_demo import require
from a18_2_demo import Gate
from a19_2_demo import upload_path
import a19_2_fixture as fixture


def endpoint(fmt):
    return upload_path(fmt).removeprefix('/api/bri-local')


class Fault:
    def __init__(self, corrupt):
        self.arrived, self.release, self.finished = Event(), Event(), Event()
        self.corrupt = corrupt
        self.reply = None


class ObservedIntake(Gate):
    def __init__(self, app):
        super().__init__(app)
        self.faults, self.commands = {}, []
        self.commands_lock = Lock()

    @contextmanager
    def arm(self, fmt, *, corrupt=False):
        path, fault = endpoint(fmt), Fault(corrupt)
        with self.commands_lock:
            require(path not in self.faults, 'Upload fault already armed')
            self.faults[path] = fault
        try:
            yield fault
        finally:
            fault.release.set()
            with self.commands_lock:
                if self.faults.get(path) is fault:
                    self.faults.pop(path)

    def seen(self):
        with self.commands_lock:
            return tuple(self.commands)

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST' or scope['path'] not in tuple(map(endpoint, fixture.FORMATS)):
            return await super().__call__(scope, receive, send)
        # The allowlisted command fields remain in process memory; never observe
        # Authorization, a cookie, scoped context, or an uploaded original on disk.
        headers = dict(scope['headers'])
        key = headers.get(b'idempotency-key', b'')
        node = headers.get(b'x-node-id', b'')
        metadata = sha256(headers.get(b'x-bri-metadata', b'')).digest()
        content = sha256()
        with self.commands_lock:
            fault = self.faults.pop(scope['path'], None)
        start, status = None, None
        reply_body = bytearray()

        async def observe_request():
            message = await receive()
            if message['type'] == 'http.request':
                content.update(message.get('body', b''))
            return message

        async def observe_response(message):
            nonlocal start, status
            if message['type'] == 'http.response.start':
                status = message['status']
                if fault:
                    start = message
                    return
            if fault and message['type'] == 'http.response.body':
                reply_body.extend(message.get('body', b''))
                require(len(reply_body) <= 4096, 'Unexpected native receipt size')
                if message.get('more_body'):
                    return
            if message['type'] == 'http.response.body' and not message.get('more_body'):
                with self.commands_lock:
                    self.commands.append((key, node, metadata, content.hexdigest(), status))
                if fault:
                    require(start is not None and status == 202, 'Fault requires real native HTTP 202')
                    raw = bytes(reply_body)
                    fault.reply = json.loads(raw)
                    fault.arrived.set()
                    async with asyncio.timeout(25):
                        while not fault.release.is_set():
                            await asyncio.sleep(.01)
                    await send(start)
                    # Preserve ASGI status and wire length. Only the actual
                    # native response body is corrupted, not the bridge.
                    message = message | {'body': b'!' * len(raw) if fault.corrupt else raw}
            await send(message)

        try:
            await self.app(scope, observe_request, observe_response)
        finally:
            if fault:
                fault.finished.set()


def setup(args, scratch, stack):
    with patch.object(fixture, 'Gate', ObservedIntake):
        return fixture.setup(args, scratch, stack, enabled=True)


def committed_fault(data, fmt, fault, original, *, who=None):
    require(fault.arrived.wait(10), 'Real native receipt did not reach ASGI send barrier')
    job = UUID(fault.reply['id'])
    require(fault.reply == {'id': str(job), 'state': 'ready'}, 'Unexpected pre-fault native receipt')
    # The exact held AM1 fixture predates the optional second-owner argument.
    if who is None:
        fixture.assert_job(data, fmt, job, original, 'ready')
    else:
        fixture.assert_job(data, fmt, job, original, 'ready', who=who)
    gate = data['gates'][fmt]
    key, node, _, digest, status = gate.seen()[-1]
    with data['fixture'].connect('postgres') as owner:
        row = owner.execute(f'SELECT request_key FROM bri.{fmt}_jobs WHERE (tenant_id,job_id)=(%s,%s)',
                            (data['fixture'].tenant, job)).fetchone()
    require(row == (UUID(key.decode()),) and node.decode() == data['scopes']['social']
            and digest == sha256(original).hexdigest() and status == 202,
            'Independent committed native command did not match the signed upload')
    return job
