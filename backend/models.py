from pydantic import BaseModel
from typing import List, Optional

class SastFinding(BaseModel):
    issue_type: str
    description: str
    file_name: str
    line_number: int
    severity: str

class ScaFinding(BaseModel):
    package: str
    version: str
    cve_id: str
    severity: str
    description: str

class ScanRequest(BaseModel):
    source_code: str
    dependencies: str
    file_name: Optional[str] = "main.py"

class ScanResponse(BaseModel):
    sast_findings: List[SastFinding]
    sca_findings: List[ScaFinding]
