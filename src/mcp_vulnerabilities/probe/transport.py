import json
import logging
import subprocess
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class TransportError(Exception):
    pass


class TransportTimeoutError(TransportError):
    pass


class BaseTransport(ABC):
    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def send(self, message: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    def receive(self, timeout: float = 5.0) -> Dict[str, Any]:
        pass


class StdioTransport(BaseTransport):
    def __init__(self, command: str):
        self.command = command
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> None:
        import shlex

        try:
            self.process = subprocess.Popen(
                shlex.split(self.command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )
        except Exception as e:
            raise TransportError(f"Failed to start subprocess: {e}")

    def stop(self) -> None:
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def send(self, message: Dict[str, Any]) -> None:
        if not self.process or not self.process.stdin:
            raise TransportError("Transport is not active.")
        try:
            line = json.dumps(message) + "\n"
            self.process.stdin.write(line)
            self.process.stdin.flush()
        except Exception as e:
            raise TransportError(f"Failed to send message: {e}")

    def receive(self, timeout: float = 5.0) -> Dict[str, Any]:
        if not self.process or not self.process.stdout:
            raise TransportError("Transport is not active.")

        # Read line with timeout using a thread
        result: list[Optional[str]] = [None]
        error: list[Optional[Exception]] = [None]

        def read_line():
            try:
                # readline blocks
                line = self.process.stdout.readline()
                result[0] = line
            except Exception as e:
                error[0] = e

        t = threading.Thread(target=read_line, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            # Stop the process to unblock readline if possible
            self.stop()
            raise TransportTimeoutError(
                f"Timeout of {timeout}s exceeded while waiting for response."
            )

        if error[0]:
            raise TransportError(f"Error reading response: {error[0]}")

        line = result[0]
        if not line:
            # Check if process exited
            if self.process.poll() is not None:
                raise TransportError("Subprocess exited unexpectedly.")
            raise TransportError("Empty response received.")

        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            raise TransportError(f"Invalid JSON response: {e}, raw: {line}")


class TransportAuthError(TransportError):
    pass


class TransportProtocolError(TransportError):
    pass


class HttpSseTransport(BaseTransport):
    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 5.0,
        insecure: bool = False,
    ):
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout
        self.insecure = insecure
        self.endpoint: Optional[str] = None
        self.sse_response: Optional[Any] = None
        self.sse_thread: Optional[threading.Thread] = None
        self.queue: list[Dict[str, Any]] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._error: Optional[Exception] = None
        self._endpoint_event = threading.Event()

    def _get_ssl_context(self):
        from mcp_vulnerabilities.ssl_utils import get_ssl_context
        return get_ssl_context(insecure=self.insecure)

    def start(self) -> None:
        import urllib.request
        import urllib.error

        self._stop_event.clear()
        self._endpoint_event.clear()
        self.queue.clear()
        self._error = None

        req_headers = dict(self.headers)
        req_headers["Accept"] = "text/event-stream"
        req_headers["Cache-Control"] = "no-cache"

        req = urllib.request.Request(self.url, headers=req_headers)

        try:
            self.sse_response = urllib.request.urlopen(
                req, timeout=self.timeout, context=self._get_ssl_context()
            )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise TransportAuthError(f"Authentication failed: HTTP {e.code}")
            raise TransportError(f"HTTP error during SSE connection: {e}")
        except urllib.error.URLError as e:
            raise TransportError(f"URL error during SSE connection: {e}")
        except Exception as e:
            raise TransportError(f"Failed to connect to SSE endpoint: {e}")

        def read_sse():
            try:
                buffer = ""
                event_name = None
                while not self._stop_event.is_set():
                    try:
                        line = self.sse_response.readline()
                    except TimeoutError:
                        continue
                    if not line:
                        break
                    try:
                        decoded = line.decode("utf-8")
                    except UnicodeDecodeError:
                        continue

                    if not decoded.strip():
                        # End of event
                        if event_name == "endpoint" and buffer:
                            import urllib.parse

                            self.endpoint = urllib.parse.urljoin(
                                self.url, buffer.strip()
                            )
                            self._endpoint_event.set()
                        elif event_name == "message" and buffer:
                            try:
                                msg = json.loads(buffer)
                                with self._lock:
                                    self.queue.append(msg)
                            except json.JSONDecodeError:
                                pass
                        buffer = ""
                        event_name = None
                        continue

                    if decoded.startswith("event:"):
                        event_name = decoded[6:].strip()
                    elif decoded.startswith("data:"):
                        buffer += decoded[5:].strip()
            except Exception as e:
                if not self._stop_event.is_set():
                    self._error = e
            finally:
                self.stop()

        self.sse_thread = threading.Thread(target=read_sse, daemon=True)
        self.sse_thread.start()

        # Wait for endpoint event
        if not self._endpoint_event.wait(timeout=self.timeout):
            self.stop()
            raise TransportProtocolError("Timeout waiting for 'endpoint' SSE event.")

    def stop(self) -> None:
        self._stop_event.set()
        if self.sse_response:
            try:
                self.sse_response.close()
            except Exception:
                pass
            self.sse_response = None
        if self.sse_thread and self.sse_thread.is_alive():
            try:
                # We can't interrupt readline directly safely, but closing the socket usually does it
                pass
            except Exception:
                pass

    def send(self, message: Dict[str, Any]) -> None:
        if not self.endpoint:
            raise TransportError("Transport is not fully initialized (no endpoint).")
        import urllib.request
        import urllib.error

        req_headers = dict(self.headers)
        req_headers["Content-Type"] = "application/json"
        data = json.dumps(message).encode("utf-8")

        req = urllib.request.Request(
            self.endpoint, data=data, headers=req_headers, method="POST"
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self._get_ssl_context()
            ) as response:
                response.read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise TransportAuthError(f"Authentication failed: HTTP {e.code}")
            raise TransportError(f"HTTP error during POST: {e}")
        except Exception as e:
            raise TransportError(f"Failed to send message: {e}")

    def receive(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        if timeout is None:
            timeout = self.timeout

        import time

        start = time.time()
        while True:
            if self._error:
                raise TransportError(f"Error in SSE stream: {self._error}")
            if self._stop_event.is_set():
                raise TransportError("SSE stream closed unexpectedly.")
            with self._lock:
                if self.queue:
                    return self.queue.pop(0)
            if time.time() - start > timeout:
                raise TransportTimeoutError(
                    f"Timeout of {timeout}s exceeded while waiting for response."
                )
            time.sleep(0.05)
