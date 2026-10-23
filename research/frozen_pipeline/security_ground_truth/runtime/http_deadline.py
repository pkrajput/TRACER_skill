"""Killable HTTP transport with a wall-clock deadline, including drip responses.

The spawned worker has no ledger or retry authority. Secrets travel in process
arguments through multiprocessing's private pipe, never in command-line text.
Only the parent settles billing after a fully returned response.
"""
import http.client
import io
import json
import multiprocessing
from multiprocessing.connection import wait
from pathlib import Path
import tempfile
import time
import threading
import urllib.error
import urllib.request

HARD_TIMEOUT_SECONDS=240
_PROCESS_LIFECYCLE = threading.Lock()


class RequestDeadlineExceeded(RuntimeError):
    """No response tokens reached the caller before the hard deadline."""

    def __init__(self, message, *, tokens_returned=0):
        super().__init__(message)
        self.tokens_returned=tokens_returned


def _worker(url,data,headers,timeout,output):
    try:
        request=urllib.request.Request(url,data=data,headers=headers)
        with urllib.request.urlopen(request,timeout=timeout) as response:
            result={'kind':'response','value':json.load(response)}
    except urllib.error.HTTPError as error:
        result={'kind':'http_error','code':error.code,'body':error.read(32768).decode(errors='replace'),
                'retry_after':error.headers.get('Retry-After') if error.headers else None}
    except Exception as error:
        # No exception repr: transport exceptions may contain key-bearing URLs.
        result={'kind':'transport_error','type':type(error).__name__}
    Path(output).write_text(json.dumps(result))


def request_json(request,*,timeout=HARD_TIMEOUT_SECONDS):
    timeout=min(float(timeout),HARD_TIMEOUT_SECONDS)
    if timeout<=0:raise ValueError('HTTP deadline must be positive')
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='tracer-http-') as directory:
        output=Path(directory)/'response.json'
        worker=multiprocessing.get_context('spawn').Process(target=_worker,
            args=(request.full_url,request.data,dict(request.header_items()),timeout,str(output)),daemon=True)
        # Process.start() polls other children during multiprocessing cleanup.
        # Serialize that bookkeeping with join/close, while HTTP waits remain
        # concurrent; otherwise another thread can reap a child during join.
        with _PROCESS_LIFECYCLE:
            worker.start()
        try:
            if not wait([worker.sentinel],max(0,timeout-(time.monotonic()-started))):
                raise RequestDeadlineExceeded(
                    'HTTP wall-clock deadline exceeded before any response tokens were returned; retain the unknown-cost reservation')
            with _PROCESS_LIFECYCLE:
                worker.join()
                if worker.exitcode!=0 or not output.exists():raise ConnectionError('HTTP worker ended without a response')
            result=json.loads(output.read_text())
        finally:
            with _PROCESS_LIFECYCLE:
                if worker.is_alive():worker.kill()
                worker.join();worker.close()
    if result['kind']=='response':return result['value']
    if result['kind']=='http_error':
        headers={'Retry-After':result['retry_after']} if result.get('retry_after') else {}
        raise urllib.error.HTTPError(request.full_url,result['code'],'HTTP provider error',headers,io.BytesIO(result['body'].encode()))
    if result['type'] in {'TimeoutError','socket.timeout'}:raise TimeoutError('HTTP inactivity timeout')
    if result['type'] in {'JSONDecodeError','UnicodeDecodeError'}:raise ValueError('Invalid provider JSON')
    raise ConnectionError('HTTP transport failed: '+result['type'])
