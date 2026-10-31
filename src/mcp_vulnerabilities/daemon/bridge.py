import asyncio
import json
import secrets
import hashlib
import base64
import urllib.parse
import re
from typing import Optional, Dict

class BridgeDaemon:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765, simulate: bool = False):
        if host not in ("127.0.0.1", "::1"):
            raise ValueError(f"Binding to {host} is not allowed. Only loopback addresses are permitted.")
        self.host = host
        self.port = port
        self.simulate = simulate
        self.session_token = secrets.token_hex(16)
        self.server: Optional[asyncio.AbstractServer] = None

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    def _is_valid_origin(self, origin: str) -> bool:
        if origin == "https://jmartynov.github.io":
            return True
        if re.match(r"^http://localhost(:\d+)?$", origin):
            return True
        if re.match(r"^http://127\.0\.0\.1(:\d+)?$", origin):
            return True
        return False

    def _get_cors_headers(self, origin: str) -> Dict[str, str]:
        if not origin:
            return {}
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-MCP-Bridge-Token"
        }

    def _send_response(self, writer, status_code: int, status_text: str, extra_headers: dict, body: bytes):
        headers = {
            "Content-Length": str(len(body)),
            "Content-Type": "application/json",
            "Connection": "close"
        }
        headers.update(extra_headers)
        
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for k, v in headers.items():
            response += f"{k}: {v}\r\n"
        response += "\r\n"
        writer.write(response.encode('utf-8') + body)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await reader.readline()
            if not request_line:
                return
            request_line_str = request_line.decode('utf-8').strip()
            if not request_line_str:
                return
            
            parts = request_line_str.split(" ")
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]

            headers = {}
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                line_str = line.decode('utf-8').strip()
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            origin = headers.get("origin")
            if origin and not self._is_valid_origin(origin):
                self._send_response(writer, 403, "Forbidden", {}, b"")
                return

            cors_headers = self._get_cors_headers(origin)

            if method == "OPTIONS":
                self._send_response(writer, 200, "OK", cors_headers, b"")
                return
                
            parsed_url = urllib.parse.urlparse(path)
            query = urllib.parse.parse_qs(parsed_url.query)

            if method == "POST":
                # We need to drain the reader to avoid server disconnect in tests
                try:
                    content_length = int(headers.get("content-length", 0))
                    if content_length > 0:
                        await reader.readexactly(content_length)
                except Exception:
                    pass

                token = headers.get("x-mcp-bridge-token")
                if token != self.session_token:
                    self._send_response(writer, 401, "Unauthorized", cors_headers, json.dumps({"error": "unauthorized"}).encode())
                    return
                # Allow dummy POST to pass for now.
                self._send_response(writer, 200, "OK", cors_headers, json.dumps({"status": "post ok"}).encode())
                return

            if parsed_url.path == "/health":
                self._send_response(writer, 200, "OK", cors_headers, json.dumps({"status": "ok"}).encode())
            elif parsed_url.path == "/api/v1/auth/challenge":
                self._send_response(writer, 200, "OK", cors_headers, json.dumps({"token": self.session_token}).encode())
            elif parsed_url.path == "/api/v1/events":
                simulate_query = query.get("simulate", ["false"])[0].lower() == "true"
                is_simulation = self.simulate or simulate_query
                await self._handle_sse(writer, is_simulation, cors_headers)
            elif parsed_url.path == "/ws/live":
                simulate_query = query.get("simulate", ["false"])[0].lower() == "true"
                is_simulation = self.simulate or simulate_query
                await self._handle_websocket(reader, writer, headers, is_simulation)
            else:
                self._send_response(writer, 404, "Not Found", cors_headers, b"")
                
        except Exception as e:
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _handle_sse(self, writer: asyncio.StreamWriter, simulate: bool, cors_headers: dict):
        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
        headers.update(cors_headers)
        
        response = "HTTP/1.1 200 OK\r\n"
        for k, v in headers.items():
            response += f"{k}: {v}\r\n"
        response += "\r\n"
        writer.write(response.encode('utf-8'))
        await writer.drain()

        if simulate:
            events = [
                {"step": "discovering_clients", "percent": 25, "message": "Discovered 14 AI clients"},
                {"step": "probing_ports", "percent": 60, "message": "Probing ports 3000-8800"},
                {"step": "analyzing_drift", "percent": 85, "message": "Comparing with SecurityPicture"},
                {"step": "done", "percent": 100, "servers_found": 8, "vulnerabilities": 1}
            ]
            for i, ev in enumerate(events):
                event_name = "scan_progress" if ev["step"] != "done" else "scan_complete"
                data = json.dumps(ev)
                chunk = f"event: {event_name}\ndata: {data}\n\n"
                writer.write(chunk.encode('utf-8'))
                await writer.drain()
                if i < len(events) - 1:
                    await asyncio.sleep(0.05)

    async def _handle_websocket(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, headers: dict, is_simulation: bool):
        ws_key = headers.get("sec-websocket-key")
        if not ws_key:
            self._send_response(writer, 400, "Bad Request", {}, b"Missing Sec-WebSocket-Key")
            return
        
        ws_accept = base64.b64encode(hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode('utf-8')).digest()).decode('utf-8')
        
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {ws_accept}\r\n\r\n"
        )
        writer.write(response.encode('utf-8'))
        await writer.drain()

        async def ws_reader():
            while True:
                try:
                    header = await reader.readexactly(2)
                    fin = (header[0] & 0x80) != 0
                    opcode = header[0] & 0x0F
                    
                    if opcode == 0x8: # close
                        break
                        
                    has_mask = (header[1] & 0x80) != 0
                    payload_len = header[1] & 0x7F
                    
                    if payload_len == 126:
                        ext_len = await reader.readexactly(2)
                        payload_len = int.from_bytes(ext_len, byteorder='big')
                    elif payload_len == 127:
                        ext_len = await reader.readexactly(8)
                        payload_len = int.from_bytes(ext_len, byteorder='big')
                        
                    if has_mask:
                        masking_key = await reader.readexactly(4)
                    else:
                        masking_key = None
                        
                    payload_data = await reader.readexactly(payload_len)
                    
                    if has_mask:
                        unmasked = bytearray(payload_len)
                        for i in range(payload_len):
                            unmasked[i] = payload_data[i] ^ masking_key[i % 4]
                        payload_data = unmasked
                        
                    if opcode == 0x1:
                        pass
                    
                except asyncio.IncompleteReadError:
                    break
                except Exception as e:
                    break
        
        read_task = asyncio.create_task(ws_reader())

        try:
            if is_simulation:
                events = [
                    {"step": "discovering_clients", "percent": 25, "message": "Discovered 14 AI clients"},
                    {"step": "probing_ports", "percent": 60, "message": "Probing ports 3000-8800"},
                    {"step": "analyzing_drift", "percent": 85, "message": "Comparing with SecurityPicture"},
                    {"step": "done", "percent": 100, "servers_found": 8, "vulnerabilities": 1}
                ]
                for i, ev in enumerate(events):
                    payload = json.dumps(ev).encode('utf-8')
                    frame = bytearray()
                    frame.append(0x81)
                    if len(payload) < 126:
                        frame.append(len(payload))
                    elif len(payload) < 65536:
                        frame.append(126)
                        frame.extend(len(payload).to_bytes(2, byteorder='big'))
                    else:
                        frame.append(127)
                        frame.extend(len(payload).to_bytes(8, byteorder='big'))
                    frame.extend(payload)
                    writer.write(frame)
                    await writer.drain()
                    if i < len(events) - 1:
                        await asyncio.sleep(0.05)
                
                writer.write(bytes([0x88, 0x00]))
                await writer.drain()
                
            await read_task
        except Exception:
            pass

def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Vuln Local Daemon Bridge")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on")
    parser.add_argument("--simulate", action="store_true", help="Enable simulation mode for SSE/WS streaming")
    args = parser.parse_args()
    
    daemon = BridgeDaemon(port=args.port, simulate=args.simulate)
    
    async def run():
        await daemon.start()
        print(f"BridgeDaemon listening on {daemon.host}:{daemon.port}")
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await daemon.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()


def run_bridge_server(args):
    """Run secure local loopback bridge server."""
    import sys
    host = getattr(args, 'host', '127.0.0.1')
    port = getattr(args, 'port', 8765)
    simulate = getattr(args, 'simulate', False) or getattr(args, 'mock', False)
    
    daemon = BridgeDaemon(host=host, port=port, simulate=simulate)
    
    async def run():
        await daemon.start()
        print(f"BridgeDaemon listening on {daemon.host}:{daemon.port}")
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await daemon.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
