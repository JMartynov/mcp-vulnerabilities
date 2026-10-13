import json
import logging
import uuid
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler
from typing import Any

logger = logging.getLogger(__name__)

def format_error(code: str, message: str, details: Any = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}

class ApiRequestHandler(BaseHTTPRequestHandler):
    router: Callable = None
    cors_origins: str | None = None
    server_instance = None

    def log_message(self, format, *args):
        try:
            log_entry = {
                "client_ip": self.client_address[0],
                "method": self.command,
                "path": self.path,
                "status": args[1] if len(args) > 1 else None,
                "message": format % args,
            }
            logger.info(json.dumps(log_entry))
        except Exception:
            pass # fallback

    def _send_cors_headers(self):
        if self.cors_origins:
            self.send_header('Access-Control-Allow-Origin', self.cors_origins)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def process_request(self):
        req_id = str(uuid.uuid4())
        try:
            status, headers, response_data = self.router(self, self.server_instance)
            
            self.send_response(status)
            self._send_cors_headers()
            self.send_header('X-Request-ID', req_id)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            
            if response_data is not None:
                if isinstance(response_data, dict) or isinstance(response_data, list):
                    self.wfile.write(json.dumps(response_data).encode('utf-8'))
                elif isinstance(response_data, str):
                    self.wfile.write(response_data.encode('utf-8'))
                else:
                    self.wfile.write(response_data)
        except Exception as e:
            logger.exception("Internal Server Error")
            if not self._headers_buffer: # If headers not sent
                self.send_response(500)
                self._send_cors_headers()
                self.send_header('X-Request-ID', req_id)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_payload = format_error("INTERNAL_ERROR", "An internal error occurred", str(e))
                self.wfile.write(json.dumps(error_payload).encode('utf-8'))

    def do_GET(self):
        self.process_request()

    def do_POST(self):
        self.process_request()
