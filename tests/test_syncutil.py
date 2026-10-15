import asyncio
import threading

from huntcrew.syncutil import run_blocking


def test_runs_directly_without_a_loop():
    main = threading.get_ident()
    assert run_blocking(lambda: threading.get_ident()) == main


def test_runs_in_a_worker_thread_when_a_loop_is_running():
    main = threading.get_ident()

    async def inside_loop():
        def probe():
            try:
                asyncio.get_running_loop()
                has_loop = True
            except RuntimeError:
                has_loop = False
            return threading.get_ident(), has_loop
        return run_blocking(probe)

    tid, has_loop = asyncio.run(inside_loop())
    assert tid != main and has_loop is False
