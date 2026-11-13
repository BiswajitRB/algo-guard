#!/usr/bin/env python3
"""
AlgoGuard Python AST Engine.
Detects CPU bombs, artificial thread sleeps, memory bombs, and backdoors in Python (FastAPI, Flask, Django).
Uses Python's standard library 'ast' module (Zero external dependencies).
"""

import ast
import json
import sys
import os

class PythonAlgoGuardVisitor(ast.NodeVisitor):
    def __init__(self, file_path, source_lines):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings = []
        self.current_route = None

    def visit_FunctionDef(self, node):
        prev_route = self.current_route
        # Check if function has route decorators (@app.get, @app.route, @router.post, etc.)
        for decorator in node.decorator_list:
            route_info = self._extract_route(decorator)
            if route_info:
                self.current_route = route_info
                break

        self.generic_visit(node)
        self.current_route = prev_route

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def _extract_route(self, node):
        if isinstance(node, ast.Call):
            func = node.func
            method = "GET"
            if isinstance(func, ast.Attribute):
                method = func.attr.upper()
                if method not in ["GET", "POST", "PUT", "DELETE", "PATCH", "ROUTE"]:
                    method = "ENDPOINT"
            path = "/api"
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                path = node.args[0].value
            return f"{method} {path}"
        return None

    def visit_For(self, node):
        # Detect: for i in range(factor * 100000) or huge ranges
        if isinstance(node.iter, ast.Call):
            func = node.iter.func
            if isinstance(func, ast.Name) and func.id == "range":
                args = node.iter.args
                target_arg = args[0] if len(args) == 1 else (args[1] if len(args) > 1 else None)
                if target_arg:
                    if self._is_high_multiplier_or_large(target_arg):
                        self.findings.append({
                            "ruleId": "UNBOUNDED_CPU_LOOP",
                            "severity": "CRITICAL",
                            "filePath": self.file_path,
                            "line": node.lineno,
                            "column": node.col_offset,
                            "route": self.current_route or "Python Function",
                            "snippet": self._get_snippet(node.lineno),
                            "message": "Python range() iteration bound is multiplied by input or exceeds safe threshold. High CPU DoS risk.",
                            "attackVector": {
                                "parameter": "range_factor",
                                "exploitValue": 1000,
                                "description": "Sending large multiplier forces Python interpreter into astronomical loop count."
                            }
                        })
        self.generic_visit(node)

    def visit_Call(self, node):
        # Detect: time.sleep(...) or asyncio.sleep(...)
        func = node.func
        is_sleep = False
        duration = None

        if isinstance(func, ast.Attribute) and func.attr == "sleep":
            if isinstance(func.value, ast.Name) and func.value.id in ["time", "asyncio"]:
                is_sleep = True
        elif isinstance(func, ast.Name) and func.id == "sleep":
            is_sleep = True

        if is_sleep:
            if node.args and isinstance(node.args[0], ast.Constant):
                duration = node.args[0].value
            
            if duration is None or (isinstance(duration, (int, float)) and duration >= 1):
                self.findings.append({
                    "ruleId": "ARTIFICIAL_THREAD_SLEEP",
                    "severity": "CRITICAL",
                    "filePath": self.file_path,
                    "line": node.lineno,
                    "column": node.col_offset,
                    "route": self.current_route or "Python Function",
                    "snippet": self._get_snippet(node.lineno),
                    "message": f"Blocking sleep call detected in Python request path ({duration or 'dynamic'}s). Causes worker pool starvation (Uvicorn/Gunicorn).",
                    "attackVector": {
                        "parameter": "trigger_condition",
                        "exploitValue": True,
                        "description": "Starves Gunicorn/Uvicorn worker threads, inducing 504 Gateway Timeouts."
                    }
                })

        # Detect: bytearray(size * 1024 * 1024) or bytes(...)
        if isinstance(func, ast.Name) and func.id in ["bytearray", "bytes"]:
            if node.args and self._is_high_multiplier_or_large(node.args[0]):
                self.findings.append({
                    "ruleId": "UNBOUNDED_MEMORY_ALLOCATION",
                    "severity": "CRITICAL",
                    "filePath": self.file_path,
                    "line": node.lineno,
                    "column": node.col_offset,
                    "route": self.current_route or "Python Function",
                    "snippet": self._get_snippet(node.lineno),
                    "message": "Dynamic byte/memory allocation size directly scaled from variable without bounds. Immediate OOM risk.",
                    "attackVector": {
                        "parameter": "chunk_size",
                        "exploitValue": 1024,
                        "description": "Triggers MemoryError or OS Out-Of-Memory (OOM) killer."
                    }
                })

        self.generic_visit(node)

    def visit_If(self, node):
        # Detect: if data.get("ticket") == "magic_token" or if req.args.get(...) == "..."
        test = node.test
        if isinstance(test, ast.Compare):
            left = test.left
            comparators = test.comparators
            if comparators and isinstance(comparators[0], ast.Constant) and isinstance(comparators[0].value, str):
                magic_token = comparators[0].value
                # Check if body returns admin privileges
                if self._returns_elevated(node.body):
                    param_name = self._extract_var_name(left)
                    self.findings.append({
                        "ruleId": "AUTH_SHORT_CIRCUIT_BACKDOOR",
                        "severity": "CRITICAL",
                        "filePath": self.file_path,
                        "line": node.lineno,
                        "column": node.col_offset,
                        "route": self.current_route or "Python Function",
                        "snippet": self._get_snippet(node.lineno),
                        "message": f"Python auth backdoor: Branch comparison against magic token '{magic_token}' returns elevated permissions.",
                        "attackVector": {
                            "parameter": param_name or "auth_key",
                            "exploitValue": magic_token,
                            "description": "Bypasses authentication and directly returns admin privileges."
                        }
                    })
        self.generic_visit(node)

    def _returns_elevated(self, body_nodes):
        for stmt in body_nodes:
            if isinstance(stmt, ast.Return):
                code_str = ast.dump(stmt).lower()
                if "admin" in code_str or "token" in code_str or "authenticated" in code_str or "role" in code_str:
                    return True
        return False

    def _extract_var_name(self, node):
        if isinstance(node, ast.Call):
            # data.get("param")
            if node.args and isinstance(node.args[0], ast.Constant):
                return str(node.args[0].value)
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant):
                return str(node.slice.value)
        if isinstance(node, ast.Name):
            return node.id
        return "flag"

    def _is_high_multiplier_or_large(self, node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)) and node.value >= 50000:
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            if self._has_large_number(node.right) or self._has_large_number(node.left):
                return True
        return False

    def _has_large_number(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and node.value >= 1000:
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return self._has_large_number(node.left) or self._has_large_number(node.right)
        return False

    def _get_snippet(self, line_num):
        idx = max(0, line_num - 1)
        lines = self.source_lines[idx:idx + 3]
        return "\n".join(lines)


def scan_python_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        tree = ast.parse(content, filename=file_path)
        visitor = PythonAlgoGuardVisitor(file_path, lines)
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        return []


def main():
    if len(sys.argv) < 2:
        print(json.dumps([]))
        return

    target = sys.argv[1]
    all_findings = []

    if os.path.isfile(target):
        if target.endswith(".py"):
            all_findings.extend(scan_python_file(target))
    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            if "node_modules" in root or ".git" in root or "__pycache__" in root:
                continue
            for f in files:
                if f.endswith(".py"):
                    full_p = os.path.join(root, f)
                    all_findings.extend(scan_python_file(full_p))

    print(json.dumps(all_findings))

if __name__ == "__main__":
    main()
