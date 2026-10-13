import ast
from typing import List, Dict, Optional
from .models import TaintFinding, TaintSinkCategory, TaintState, KNOWN_SANITIZERS


class McpToolAstVisitor(ast.NodeVisitor):
    def __init__(self, source_code: str, file_path: Optional[str] = None):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[TaintFinding] = []
        self.functions: Dict[str, ast.FunctionDef] = {}

        # Current state
        self.in_tool_function = False
        self.current_tool_name = ""
        self.tainted_vars: Dict[str, TaintState] = {}  # var_name -> TaintState
        self.param_lines: Dict[str, int] = {}
        self.call_stack = set()

    def visit_Module(self, node: ast.Module):
        for stmt in node.body:
            if isinstance(stmt, ast.FunctionDef):
                self.functions[stmt.name] = stmt
        self.generic_visit(node)

    def _get_snippet(self, node: ast.AST) -> str:
        if hasattr(node, 'lineno') and hasattr(node, 'end_lineno') and node.lineno and node.end_lineno:
            start = max(0, node.lineno - 1)
            end = node.end_lineno
            return "\n".join(self.source_lines[start:end])
        return ""

    def _is_tool_decorator(self, decorator: ast.AST) -> bool:
        if isinstance(decorator, ast.Name):
            return decorator.id in {"tool"}
        elif isinstance(decorator, ast.Attribute):
            if isinstance(decorator.value, ast.Name):
                return decorator.value.id in {"mcp", "server", "app", "FastMCP"} and decorator.attr == "tool"
        elif isinstance(decorator, ast.Call):
            return self._is_tool_decorator(decorator.func)
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        is_tool = any(self._is_tool_decorator(d) for d in node.decorator_list)
        if not is_tool:
            self.generic_visit(node)
            return

        self.in_tool_function = True
        self.current_tool_name = node.name
        self.tainted_vars.clear()
        self.param_lines.clear()

        # Mark parameters as tainted
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            self.tainted_vars[arg.arg] = TaintState(parameter_name=arg.arg, sanitized_categories=set())
            self.param_lines[arg.arg] = node.lineno

        if node.args.vararg:
            self.tainted_vars[node.args.vararg.arg] = TaintState(parameter_name=node.args.vararg.arg, sanitized_categories=set())
            self.param_lines[node.args.vararg.arg] = node.lineno

        if node.args.kwarg:
            self.tainted_vars[node.args.kwarg.arg] = TaintState(parameter_name=node.args.kwarg.arg, sanitized_categories=set())
            self.param_lines[node.args.kwarg.arg] = node.lineno

        self.generic_visit(node)

        self.in_tool_function = False
        self.current_tool_name = ""
        self.tainted_vars.clear()
        self.param_lines.clear()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _combine_taints(self, taints: List[TaintState]) -> Optional[TaintState]:
        if not taints:
            return None
        if len(taints) == 1:
            return taints[0]
        
        # Merge taints: keep the intersection of sanitized categories
        # because if ANY part is unsanitized, the whole is unsanitized for that category.
        intersection = set(TaintSinkCategory)
        names = []
        for t in taints:
            intersection.intersection_update(t.sanitized_categories)
            if t.parameter_name not in names:
                names.append(t.parameter_name)
        
        return TaintState(parameter_name=", ".join(names), sanitized_categories=intersection)

    def _is_tainted(self, node: ast.AST) -> Optional[TaintState]:
        """Returns the TaintState if the node is tainted, else None."""
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return TaintState(parameter_name=self.tainted_vars[node.id].parameter_name, sanitized_categories=set(self.tainted_vars[node.id].sanitized_categories))
        elif isinstance(node, ast.Subscript):
            # For res["url"], check if res is tainted.
            return self._is_tainted(node.value)
        elif isinstance(node, ast.BinOp):
            left_taint = self._is_tainted(node.left)
            right_taint = self._is_tainted(node.right)
            return self._combine_taints([t for t in (left_taint, right_taint) if t])
        elif isinstance(node, ast.JoinedStr):
            taints = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._is_tainted(value.value)
                    if taint:
                        taints.append(taint)
            return self._combine_taints(taints)
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)
            
            # Check if this call is a known sanitizer
            is_sanitizer = call_name in KNOWN_SANITIZERS
            sanitized_cats = KNOWN_SANITIZERS.get(call_name, set())

            # Check arguments for taint
            arg_taints = []
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                t = self._is_tainted(node.func.value)
                if t:
                    arg_taints.append(t)
                for arg in node.args:
                    t = self._is_tainted(arg)
                    if t:
                        arg_taints.append(t)
                for kw in node.keywords:
                    t = self._is_tainted(kw.value)
                    if t:
                        arg_taints.append(t)
            else:
                for arg in node.args:
                    t = self._is_tainted(arg)
                    if t:
                        arg_taints.append(t)
                for kw in node.keywords:
                    t = self._is_tainted(kw.value)
                    if t:
                        arg_taints.append(t)

            call_taint = self._combine_taints(arg_taints)

            if call_taint:
                if is_sanitizer:
                    call_taint.sanitized_categories.update(sanitized_cats)
                return call_taint

        elif isinstance(node, ast.Tuple) or isinstance(node, ast.List):
            taints = []
            for elt in node.elts:
                t = self._is_tainted(elt)
                if t:
                    taints.append(t)
            return self._combine_taints(taints)
        elif isinstance(node, ast.Dict):
            taints = []
            for val in node.values:
                if val:
                    t = self._is_tainted(val)
                    if t:
                        taints.append(t)
            return self._combine_taints(taints)

        return None

    def visit_Assign(self, node: ast.Assign):
        if not self.in_tool_function:
            self.generic_visit(node)
            return

        tainted_param = self._is_tainted(node.value)
        if tainted_param:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = TaintState(parameter_name=tainted_param.parameter_name, sanitized_categories=set(tainted_param.sanitized_categories))
                elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted_vars[elt.id] = TaintState(parameter_name=tainted_param.parameter_name, sanitized_categories=set(tainted_param.sanitized_categories))
        self.generic_visit(node)
        
    def visit_AnnAssign(self, node: ast.AnnAssign):
        if not self.in_tool_function:
            self.generic_visit(node)
            return
            
        if node.value:
            tainted_param = self._is_tainted(node.value)
            if tainted_param and isinstance(node.target, ast.Name):
                self.tainted_vars[node.target.id] = TaintState(parameter_name=tainted_param.parameter_name, sanitized_categories=set(tainted_param.sanitized_categories))
                
        self.generic_visit(node)

    def _get_call_name(self, func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            val = self._get_call_name(func_node.value)
            return f"{val}.{func_node.attr}" if val else func_node.attr
        return ""

    def visit_Call(self, node: ast.Call):
        if not self.in_tool_function:
            self.generic_visit(node)
            return

        call_name = self._get_call_name(node.func)
        
        # Helper function delegation
        if call_name in self.functions and call_name not in self.call_stack:
            self.call_stack.add(call_name)
            func_def = self.functions[call_name]
            # Save state
            old_tainted_vars = self.tainted_vars.copy()
            old_param_lines = self.param_lines.copy()
            
            # Map args to params
            new_tainted_vars = {}
            all_pos_args = func_def.args.posonlyargs + func_def.args.args
            for i, arg in enumerate(node.args):
                if i < len(all_pos_args):
                    param_name = all_pos_args[i].arg
                    arg_taint = self._is_tainted(arg)
                    if arg_taint:
                        new_tainted_vars[param_name] = TaintState(parameter_name=arg_taint.parameter_name, sanitized_categories=set(arg_taint.sanitized_categories))
                        self.param_lines[param_name] = node.lineno
                        
            for kw in node.keywords:
                arg_taint = self._is_tainted(kw.value)
                if arg_taint:
                    new_tainted_vars[kw.arg] = TaintState(parameter_name=arg_taint.parameter_name, sanitized_categories=set(arg_taint.sanitized_categories))
                    self.param_lines[kw.arg] = node.lineno
            
            self.tainted_vars = new_tainted_vars
            
            # Visit target function body
            for stmt in func_def.body:
                self.visit(stmt)
                
            # Restore state
            self.tainted_vars = old_tainted_vars
            self.param_lines = old_param_lines
            self.call_stack.remove(call_name)
            
        # Check sinks
        sink_category = None
        severity = "HIGH"
        remediation = ""

        # COMMAND_INJECTION
        if call_name in {
            "os.system", "os.popen", "pty.spawn",
            "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.call", "subprocess.check_call"
        }:
            sink_category = TaintSinkCategory.COMMAND_INJECTION
            severity = "CRITICAL"
            remediation = "Use parameterized commands (lists) with shell=False, and validate input against an allowlist."
            
            # Special case for subprocess calls that are safe if the first arg is a list
            if call_name.startswith("subprocess."):
                if node.args:
                    first_arg = node.args[0]
                    # If it's a fixed list of strings, it might be safe (though elements could be tainted)
                    # We check if the command itself (or its arguments) is tainted
                    tainted_param = self._is_tainted(first_arg)
                    
                    # If shell=True is passed, it's always dangerous
                    shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
                    
                    if tainted_param and (shell_true or not isinstance(first_arg, (ast.List, ast.Tuple))):
                        # Tainted string to subprocess or shell=True
                        pass
                    elif tainted_param and isinstance(first_arg, (ast.List, ast.Tuple)):
                        # Tainted list elements. Still dangerous but maybe slightly less than shell injection
                        # We still flag it
                        pass
                    else:
                        sink_category = None # Safe

        # CODE_EVALUATION
        elif call_name in {"eval", "exec", "compile", "builtins.__import__", "__import__"}:
            sink_category = TaintSinkCategory.CODE_EVALUATION
            severity = "CRITICAL"
            remediation = "Avoid dynamic code execution. If unavoidable, use literal_eval or strictly sandbox the execution."

        # PATH_TRAVERSAL
        elif call_name in {
            "open", "os.remove", "os.unlink", "shutil.rmtree",
            "pathlib.Path.write_text", "pathlib.Path.read_text"
        } or call_name.endswith(".write_text") or call_name.endswith(".read_text"):
            sink_category = TaintSinkCategory.PATH_TRAVERSAL
            remediation = "Sanitize and resolve paths (e.g., os.path.abspath) and ensure they remain within the intended base directory."

        # SQL_INJECTION
        elif call_name in {"cursor.execute", "connection.execute"} or call_name.endswith(".execute"):
            sink_category = TaintSinkCategory.SQL_INJECTION
            severity = "CRITICAL"
            remediation = "Use parameterized queries (e.g., execute('SELECT...', (input,))) instead of string formatting."

        # SSRF_EGRESS
        elif (
            call_name in {
                "urllib.request.urlopen", "urlopen",
                "requests.get", "requests.post", "requests.put",
                "httpx.get", "httpx.post", "httpx.put",
            }
            or any(
                call_name.startswith(p) and (call_name.endswith(".get") or call_name.endswith(".post") or call_name.endswith(".request"))
                for p in ("requests.", "httpx.", "session.", "client.", "http.", "aiohttp.")
            )
        ):
            sink_category = TaintSinkCategory.SSRF_EGRESS
            remediation = "Validate URLs against an allowlist of permitted hosts/domains."

        if sink_category:
            # Check if any argument is tainted
            tainted_param = None
            for arg in node.args:
                taint = self._is_tainted(arg)
                if taint and sink_category not in taint.sanitized_categories:
                    tainted_param = taint.parameter_name
                    break
            
            if not tainted_param:
                for kw in node.keywords:
                    taint = self._is_tainted(kw.value)
                    if taint and sink_category not in taint.sanitized_categories:
                        tainted_param = taint.parameter_name
                        break

            if tainted_param:
                self.findings.append(TaintFinding(
                    tool_name=self.current_tool_name,
                    parameter_name=tainted_param,
                    source_line=self.param_lines.get(tainted_param, 0),
                    sink_call=call_name,
                    sink_category=sink_category,
                    sink_line=node.lineno,
                    severity=severity,
                    code_snippet=self._get_snippet(node),
                    remediation=remediation,
                    file_path=self.file_path
                ))

        self.generic_visit(node)
