import ast
from typing import List, Dict, Any

class SASTNodeVisitor(ast.NodeVisitor):
    def __init__(self, file_name: str):
        self.findings: List[Dict[str, Any]] = []
        self.file_name = file_name
        self.secret_keywords = ['password', 'api_key', 'secret', 'token']

    def add_finding(self, issue_type: str, severity: str, description: str, line_number: int):
        self.findings.append({
            "issue_type": issue_type,
            "severity": severity,
            "description": description,
            "file_name": self.file_name,
            "line_number": line_number
        })

    def visit_Call(self, node: ast.Call):
        # Detect Weak Cryptography (hashlib.md5, hashlib.sha1)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in ["md5", "sha1"]:
                    self.add_finding(
                        issue_type="Weak Cryptography",
                        severity="HIGH",
                        description=f"Use of weak hashing algorithm: hashlib.{node.func.attr}()",
                        line_number=node.lineno
                    )
        
        # Detect Insecure Defaults (debug=True)
        for keyword in node.keywords:
            if keyword.arg == "debug" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    self.add_finding(
                        issue_type="Insecure Default",
                        severity="MEDIUM",
                        description="Found 'debug=True' passed as an argument. This is insecure for production.",
                        line_number=node.lineno
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Detect Hardcoded Secrets
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if any(keyword in var_name for keyword in self.secret_keywords):
                        self.add_finding(
                            issue_type="Hardcoded Secret",
                            severity="CRITICAL",
                            description=f"Possible hardcoded secret assigned to variable '{target.id}'.",
                            line_number=node.lineno
                        )

        self.generic_visit(node)


def run_sast_scan(source_code: str, file_name: str = "main.py") -> List[Dict[str, Any]]:
    """
    Parses the source code using the AST and runs the visitor to find misconfigurations.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        # If code is invalid, return a parse error finding
        return [{
            "issue_type": "Syntax Error",
            "severity": "LOW",
            "description": f"Failed to parse target file: {str(e)}",
            "file_name": file_name,
            "line_number": getattr(e, "lineno", 0) or 0
        }]

    visitor = SASTNodeVisitor(file_name)
    visitor.visit(tree)
    return visitor.findings
