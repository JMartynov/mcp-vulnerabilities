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


# A simple HttpSseTransport stub can be implemented if needed, but not strictly required for the acceptance criteria for stdio
class HttpSseTransport(BaseTransport):
    def __init__(self, url: str):
        self.url = url
        raise NotImplementedError("SSE transport is not implemented yet.")

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def send(self, message: Dict[str, Any]) -> None:
        pass

    def receive(self, timeout: float = 5.0) -> Dict[str, Any]:
        return {}
