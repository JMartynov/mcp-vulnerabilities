def generate_openapi_schema(version: str = "1.0.0") -> dict:
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "MCP Security API",
            "version": version,
            "description": "Headless REST API daemon for MCP vulnerabilities, server fingerprinting, and client configuration audits."
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health Check",
                    "responses": {
                        "200": {
                            "description": "System health and status metrics",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "version": {"type": "string"},
                                            "vulnerabilities_indexed": {"type": "integer"},
                                            "passports_loaded": {"type": "integer"},
                                            "uptime_seconds": {"type": "number"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/v1/scan/probe": {
                "post": {
                    "summary": "Probe MCP Server",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "command": {"type": "string"},
                                        "url": {"type": "string"},
                                        "timeout": {"type": "number", "default": 30.0},
                                        "analyzers": {"type": "array", "items": {"type": "string"}}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Probe results"}
                    }
                }
            },
            "/api/v1/identify": {
                "post": {
                    "summary": "Identify MCP Package",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object"
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Identity match results"}
                    }
                }
            },
            "/api/v1/scan/config": {
                "post": {
                    "summary": "Scan Client Config",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "config": {"type": "object"},
                                        "detect_collisions": {"type": "boolean", "default": True}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Config scan results"}
                    }
                }
            },
            "/api/v1/vulnerabilities": {
                "get": {
                    "summary": "List Vulnerabilities",
                    "parameters": [
                        {"name": "cve", "in": "query", "schema": {"type": "string"}},
                        {"name": "tool", "in": "query", "schema": {"type": "string"}},
                        {"name": "ecosystem", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {"description": "List of OSV vulnerability records"}
                    }
                }
            }
        }
    }
