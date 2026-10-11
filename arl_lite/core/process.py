"""Cancelable stdlib subprocess execution; no orphan scanner on task cancel."""
import asyncio
import subprocess
import time


async def run_process(args, timeout):
    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        return subprocess.CompletedProcess(args, process.returncode,
                                           stdout.decode(errors="replace"), stderr.decode(errors="replace"))
    finally:
        if process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.communicate(), 1)
            except (ProcessLookupError, asyncio.TimeoutError):
                if process.returncode is None:
                    process.kill()
                    await process.communicate()


def run_process_sync(args, timeout, should_stop=lambda: False):
    """For thread-offloaded adapters: drain pipes and check stop every 100ms."""
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        started = time.monotonic()
        try:
            while True:
                if should_stop():
                    raise InterruptedError("scanner stopped")
                if time.monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired(args, timeout)
                try:
                    stdout, stderr = process.communicate(timeout=0.1)
                    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
