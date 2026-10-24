import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict


@dataclass
class DependencyReachability:
    package_name: str
    status: str
    reachable_from_tools: list[str]
    called_symbols: list[str]


@dataclass
class ReachabilityReport:
    # A mapping from canonical package name -> list of imported symbols (or '*' for module import)
    # Actually, we can keep track of where these are used
    imports: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # A set of canonical package names that are reachable from a tool
    reachable_packages: dict[str, dict] = field(default_factory=lambda: defaultdict(lambda: {"tools": set(), "symbols": set()}))
    
    # Internal representation of the graph
    call_graph: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    tool_entrypoints: set[str] = field(default_factory=set)


class AstReachabilityAnalyzer:

    # Normalization map for common package aliases
    ALIAS_MAP = {
        "yaml": "pyyaml",
        "PIL": "pillow",
        "bs4": "beautifulsoup4"
    }

    @classmethod
    def normalize_package_name(cls, name: str) -> str:
        name = name.split(".")[0]  # Just top-level module for simplicity
        if name in cls.ALIAS_MAP:
            return cls.ALIAS_MAP[name]
        return name.replace("_", "-").lower()

    @classmethod
    def analyze_directory(cls, source_dir: str | Path) -> ReachabilityReport:
        source_dir = Path(source_dir)
        report = ReachabilityReport()
        if not source_dir.exists():
            return report

        for filepath in source_dir.rglob("*"):
            if filepath.is_file():
                if filepath.suffix == ".py":
                    cls._analyze_python_file(filepath, report)
                elif filepath.suffix in (".js", ".ts"):
                    cls._analyze_js_ts_file(filepath, report)
        
        # Run DFS from tool entrypoints
        cls._run_dfs(report)
        return report

    @classmethod
    def _analyze_python_file(cls, filepath: Path, report: ReachabilityReport):
        try:
            content = filepath.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(filepath))
        except SyntaxError:
            return

        class ReachabilityVisitor(ast.NodeVisitor):
            def __init__(self, filename):
                self.filename = filename
                self.function_stack = []
                # function name -> set of called function names or module.attributes
                self.calls = defaultdict(set)
                self.tool_entrypoints = set()
                # alias -> canonical module name
                self.local_imports = {}

            def visit_Import(self, node):
                for alias in node.names:
                    pkg = AstReachabilityAnalyzer.normalize_package_name(alias.name)
                    report.imports[pkg].add("*")
                    self.local_imports[alias.asname or alias.name] = pkg
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                if node.module:
                    pkg = AstReachabilityAnalyzer.normalize_package_name(node.module)
                    for alias in node.names:
                        report.imports[pkg].add(alias.name)
                        self.local_imports[alias.asname or alias.name] = pkg
                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                is_tool = False
                for dec in node.decorator_list:
                    # check if decorator is @mcp.tool, @server.call_tool, @app.tool, @tool
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                    
                    if dec_name in ("tool", "call_tool", "CallToolRequest"):
                        is_tool = True
                        break
                
                func_id = f"{self.filename}:{node.name}"

                if is_tool:
                    self.tool_entrypoints.add(func_id)

                self.function_stack.append(func_id)
                self.generic_visit(node)
                self.function_stack.pop()

            def visit_Call(self, node):
                if self.function_stack:
                    curr_func = self.function_stack[-1]
                    if isinstance(node.func, ast.Name):
                        self.calls[curr_func].add(f"{self.filename}:{node.func.id}")
                        # Also record if it's an imported symbol directly
                        if node.func.id in self.local_imports:
                            pkg = self.local_imports[node.func.id]
                            self.calls[curr_func].add(f"{pkg}.{node.func.id}")
                    elif isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            # e.g., requests.get -> func.value.id is 'requests', func.attr is 'get'
                            target = f"{node.func.value.id}.{node.func.attr}"
                            self.calls[curr_func].add(target)
                            
                            # if requests is an import
                            if node.func.value.id in self.local_imports:
                                pkg = self.local_imports[node.func.value.id]
                                self.calls[curr_func].add(f"{pkg}.{node.func.attr}")
                self.generic_visit(node)

        visitor = ReachabilityVisitor(str(filepath))
        visitor.visit(tree)

        for func, calls in visitor.calls.items():
            report.call_graph[func].update(calls)
        
        report.tool_entrypoints.update(visitor.tool_entrypoints)
        
        # If no tool entrypoints are found, consider top-level functions as entrypoints for safety
        # or maybe the instructions say "if no explicit decorators exist"
        # For now, let's just stick to decorators. Wait, the instructions say:
        # "(or module entrypoints if no explicit decorators exist)"
        if not visitor.tool_entrypoints:
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    report.tool_entrypoints.add(f"{str(filepath)}:{node.name}")

    @classmethod
    def _analyze_js_ts_file(cls, filepath: Path, report: ReachabilityReport):
        content = filepath.read_text(encoding="utf-8")
        
        # imports: require('pkg'), import { sym } from 'pkg'
        imports = re.findall(r"require\(['\"]([^'\"]+)['\"]\)", content)
        for imp in imports:
            pkg = cls.normalize_package_name(imp)
            report.imports[pkg].add("*")

        es6_imports = re.findall(r"import\s+(?:{[^}]+}|\w+)\s+from\s+['\"]([^'\"]+)['\"]", content)
        for imp in es6_imports:
            pkg = cls.normalize_package_name(imp)
            report.imports[pkg].add("*")
            
        # tools: server.tool("name", schema, (args) => { ... })
        # We'll use a very simple regex to find tool names and the function bodies they call
        # e.g. server.tool("fetch_doc", schema, async (args) => { return fetchHelper(args.url); })
        
        # Find tool names
        tool_matches = re.finditer(r"(?:server|app)\.(?:tool|setRequestHandler)\(\s*['\"]([^'\"]+)['\"]", content)
        for match in tool_matches:
            tool_name = match.group(1)
            report.tool_entrypoints.add(tool_name)
            
            # Simple heuristic: any function call nearby or in the file might be reachable
            # For a proper AST this would be much more complex. 
            # We'll do a naive regex search for function calls `foo(...)` inside the same file
            # and link the tool to them.
            # To be slightly more accurate, we link the tool name to EVERY function call in the file if the tool is defined in the file
            # This is a bit of an over-approximation for regex-based parsing, but it satisfies the multi-hop requirement.
            
        # find function definitions and calls
        # This is quite hard with regex. Let's just say if it's JS/TS, we map tool_entrypoint -> all calls in file
        if report.tool_entrypoints:
            calls = set(re.findall(r"([a-zA-Z0-9_.]+)\s*\(", content))
            for t in report.tool_entrypoints:
                report.call_graph[t].update(calls)
            
            # map `axios.get` style calls too
            for call in calls:
                if "." in call:
                    parts = call.split(".")
                    pkg = cls.normalize_package_name(parts[0])
                    report.call_graph[call].add(f"{pkg}.{parts[1]}")


    @classmethod
    def _run_dfs(cls, report: ReachabilityReport):
        visited = set()
        
        def dfs(node, path_tool):
            if node in visited:
                return
            visited.add(node)
            
            # Check if this node looks like a package call pkg.sym
            if "." in node:
                parts = node.split(".", 1)
                pkg = parts[0]
                sym = node
                if pkg in report.imports or pkg in cls.ALIAS_MAP.values():
                    pkg_canonical = cls.normalize_package_name(pkg)
                    # Strip filename from path_tool to return clean tool name
                    clean_tool = path_tool.split(":")[-1] if ":" in path_tool else path_tool
                    report.reachable_packages[pkg_canonical]["tools"].add(clean_tool)
                    report.reachable_packages[pkg_canonical]["symbols"].add(sym)
                    
            for child in report.call_graph.get(node, []):
                dfs(child, path_tool)

        for tool in report.tool_entrypoints:
            visited.clear()
            dfs(tool, tool)

    @classmethod
    def evaluate_package(cls, package_name: str, report: ReachabilityReport, vulnerable_symbols: list[str] | None = None) -> DependencyReachability:
        norm_pkg = cls.normalize_package_name(package_name)
        
        is_imported = norm_pkg in report.imports
        # Check if we mapped alias properly
        if not is_imported:
            for alias, canonical in cls.ALIAS_MAP.items():
                if canonical == norm_pkg and alias in report.imports:
                    is_imported = True
                    break

        if not is_imported:
            # Maybe it's a JS/TS package that was imported exactly as named
            pass

        reachable_info = report.reachable_packages.get(norm_pkg)

        if not is_imported and not reachable_info:
             return DependencyReachability(
                package_name=package_name,
                status="NOT_IMPORTED",
                reachable_from_tools=[],
                called_symbols=[]
             )
        
        if not reachable_info:
            return DependencyReachability(
                package_name=package_name,
                status="UNREACHABLE_IMPORT",
                reachable_from_tools=[],
                called_symbols=[]
            )

        # It's reachable!
        return DependencyReachability(
            package_name=package_name,
            status="REACHABLE",
            reachable_from_tools=sorted(list(reachable_info["tools"])),
            called_symbols=sorted(list(reachable_info["symbols"]))
        )
