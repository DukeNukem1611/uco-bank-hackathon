# To run this code easily in a Jupyter/Colab Notebook
import ast
import re

# ================================
# 1. AST Scanner (SAST Module)
# ================================
class SASTNodeVisitor(ast.NodeVisitor):
    def __init__(self, file_name="code.py"):
        self.findings = []
        self.file_name = file_name
        self.secret_keywords = ['password', 'api_key', 'secret', 'token']

    def add_finding(self, issue_type, severity, description, line_number):
        self.findings.append({
            "issue_type": issue_type,
            "severity": severity,
            "description": description,
            "file_name": self.file_name,
            "line_number": line_number
        })

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
            if node.func.attr in ["md5", "sha1"]:
                self.add_finding("Weak Cryptography", "HIGH", f"hashlib.{node.func.attr}() usage", node.lineno)
        for keyword in node.keywords:
            if keyword.arg == "debug" and getattr(keyword.value, "value", None) is True:
                self.add_finding("Insecure Default", "MEDIUM", "debug=True in production", node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name) and any(k in target.id.lower() for k in self.secret_keywords):
                    self.add_finding("Hardcoded Secret", "CRITICAL", f"Secret in {target.id}", node.lineno)
        self.generic_visit(node)

def run_sast_scan(source_code):
    visitor = SASTNodeVisitor()
    visitor.visit(ast.parse(source_code))
    return visitor.findings

# ================================
# 2. Dependency Scanner (SCA Module)
# ================================
def check_cve_database(package, version):
    if package.lower() == 'requests' and version.startswith('2.20'):
        return [{"cve_id": "CVE-2018-18074", "severity": "HIGH", "description": "Auth header leak."}]
    return []

def run_sca_scan(reqs):
    findings = []
    for line in reqs.splitlines():
        match = re.match(r'^([a-zA-Z0-9_\-]+)(?:==|>=)([\d\.]+\w*)', line.strip())
        if match:
            for cve in check_cve_database(match.group(1), match.group(2)):
                findings.append({"package": match.group(1), "version": match.group(2), **cve})
    return findings

# ================================
# 3. Test the Modules
# ================================
test_code = """
import hashlib
api_key = "abc123xyz"
app.run(debug=True)
my_hash = hashlib.md5("hello".encode())
"""
test_reqs = "requests==2.20.0\npytest==7.0.0"

print("SAST Results:", run_sast_scan(test_code))
print("SCA Results:", run_sca_scan(test_reqs))
