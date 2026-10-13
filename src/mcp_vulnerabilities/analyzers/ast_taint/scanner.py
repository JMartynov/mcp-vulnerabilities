import ast
import os
import traceback
from pathlib import Path
from typing import List

from .models import TaintFinding
from .visitor import McpToolAstVisitor

class McpSourceScanner:
    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.findings: List[TaintFinding] = []
        self.scanned_files = 0
        self.errors = 0

    def scan(self) -> List[TaintFinding]:
        if self.target_path.is_file():
            self._scan_file(self.target_path)
        elif self.target_path.is_dir():
            for root, dirs, files in os.walk(self.target_path):
                # Skip specific directories
                dirs[:] = [d for d in dirs if d not in {".venv", "venv", "__pycache__", ".git", "node_modules", ".pytest_cache"}]
                
                for file in files:
                    if file.endswith(".py"):
                        self._scan_file(Path(root) / file)
        
        return self.findings

    def _scan_file(self, file_path: Path):
        try:
            self.scanned_files += 1
            code = file_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(file_path))
            
            visitor = McpToolAstVisitor(code, file_path=str(file_path))
            visitor.visit(tree)
            
            self.findings.extend(visitor.findings)
        except SyntaxError:
            self.errors += 1
            # Could log the syntax error
        except Exception:
            self.errors += 1
