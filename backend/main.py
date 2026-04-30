import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from models import ScanRequest, ScanResponse, SastFinding, ScaFinding
from sast import run_sast_scan
from sca import run_sca_scan

app = FastAPI(
    title="SecURI CI/CD Engine",
    description="Custom SAST and SCA Scanning API for detecting insecure defaults and CVEs.",
    version="1.0.0"
)

# Setup CORS for React Frontend Integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/scan", response_model=ScanResponse)
async def scan_code(payload: ScanRequest):
    try:
        # Run AST scanner and Dependency scanner asynchronously
        # Offloading synchronous CPU-bound ops to threads to avoid blocking the event loop
        sast_task = asyncio.to_thread(run_sast_scan, payload.source_code, payload.file_name)
        sca_task = asyncio.to_thread(run_sca_scan, payload.dependencies)

        # Wait for both scans to complete
        raw_sast_findings, raw_sca_findings = await asyncio.gather(sast_task, sca_task)

        # Parse findings into Pydantic models
        sast_findings = [SastFinding(**f) for f in raw_sast_findings]
        sca_findings = [ScaFinding(**f) for f in raw_sca_findings]

        return ScanResponse(
            sast_findings=sast_findings,
            sca_findings=sca_findings
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanning failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=8000, reload=True)
