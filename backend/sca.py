import re
from typing import List, Dict, Any

def check_cve_database(package: str, version: str) -> List[Dict[str, Any]]:
    """
    Mock function simulating an API call to a vulnerability database (e.g., NVD, OSV).
    """
    pkg = package.lower()
    findings = []

    # Dummy data for demonstration purposes
    if pkg == 'requests' and version.startswith('2.20'):
        findings.append({
            "cve_id": "CVE-2018-18074",
            "severity": "HIGH",
            "description": "The Requests package before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a redirect."
        })
    elif pkg == 'urllib3' and version.startswith('1.24'):
        findings.append({
            "cve_id": "CVE-2019-11324",
            "severity": "HIGH",
            "description": "The urllib3 library before 1.24.2 for Python mishandles certain cases where desired certification parameters are unresolved."
        })
    elif pkg == 'pyjwt' and version.startswith('1.7'):
        findings.append({
            "cve_id": "CVE-2022-29217",
            "severity": "CRITICAL",
            "description": "PyJWT before 2.4.0 lacks key type verification, which can lead to key confusion attacks."
        })

    return findings

def run_sca_scan(requirements_content: str) -> List[Dict[str, Any]]:
    """
    Parses a requirements.txt string, extracts packages/versions, and checks for CVEs.
    """
    findings = []
    # Pattern to match basic requirement format: package==1.2.3 or package>=1.2.3
    pattern = re.compile(r'^([a-zA-Z0-9_\-]+)(?:==|>=|<=|~=)([\d\.]+\w*).*')

    for line in requirements_content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        match = pattern.match(line)
        if match:
            package = match.group(1)
            version = match.group(2)
            
            cves = check_cve_database(package, version)
            for cve in cves:
                findings.append({
                    "package": package,
                    "version": version,
                    "cve_id": cve["cve_id"],
                    "severity": cve["severity"],
                    "description": cve["description"]
                })
                
    return findings
