"""Synchronize packet tests with tcpdump startup, including slow CI runners."""
import time

def wait_capture(process, log_path, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        log = log_path.read_text()
        if process.poll() is not None:
            raise RuntimeError('tcpdump exited before capture: ' + log)
        if 'listening on ' in log:
            return
        time.sleep(.05)
    raise RuntimeError('tcpdump startup timeout: ' + log_path.read_text())
