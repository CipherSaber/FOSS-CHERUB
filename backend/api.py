#!/usr/bin/env python3
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import tempfile
import shutil
import uuid
from pathlib import Path
import pandas as pd
import json
import sys

# Add parent directory to path to import from root
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import your scanner
from foss_scanner import FOSSCHERUBScanner  # Your scanner class

app = FastAPI(title="FOSS-CHERUB API", version="2.0")

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "https://your-vercel-domain.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# In-memory store (replace with PostgreSQL in production)
scans_db: Dict[str, Dict[str, Any]] = {}

# Initialize scanner (adjust paths for your setup)
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "foss_cherub",
    "user": "postgres",
    "password": "foss_cherub_2024",
}
MODEL_PATH = "/workspace/vulnerability-detection-tool/data_processing/merged_model"

scanner = FOSSCHERUBScanner(DB_CONFIG, MODEL_PATH)


class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    scan_name: Optional[str] = "Unnamed Scan"


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@app.get("/")
def root():
    return {"message": "FOSS-CHERUB API v2.0", "status": "online"}


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "FOSS-CHERUB API"}


@app.get("/api/db/status")
def check_db_status():
    """Check CVE database connection status."""
    try:
        # Test database connection
        test_result = scanner.query_cve_database("CWE-89")
        db_status = "connected" if scanner.db_conn else "disconnected"
        return {
            "database": db_status,
            "test_query_results": len(test_result),
            "sample_cve": test_result[0] if test_result else None
        }
    except Exception as e:
        return {
            "database": "error",
            "error": str(e),
            "test_query_results": 0
        }


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan from a Git repository URL."""
    scan_id = str(uuid.uuid4())

    if not request.repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required")

    scans_db[scan_id] = {
        "id": scan_id,
        "name": request.scan_name,
        "repo_url": request.repo_url,
        "status": "running",
        "findings": [],
        "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    background_tasks.add_task(run_scan_task, scan_id, request.repo_url, False)

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message=f"Scan started for {request.repo_url}",
    )


@app.post("/api/scans/upload", response_model=ScanResponse)
async def upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """Upload a ZIP/TAR file and scan it."""
    scan_id = str(uuid.uuid4())

    # Save uploaded file
    temp_dir = tempfile.mkdtemp()
    file_path = Path(temp_dir) / file.filename

    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    scans_db[scan_id] = {
        "id": scan_id,
        "name": file.filename,
        "repo_url": f"Uploaded: {file.filename}",
        "status": "running",
        "findings": [],
        "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    background_tasks.add_task(run_scan_task, scan_id, str(file_path), True)

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message="File uploaded, scanning...",
    )


def run_scan_task(scan_id: str, target_path: str, is_upload: bool) -> None:
    """Background task to run the actual scan."""
    try:
        # Clone Git repo into a temp directory if not an uploaded archive
        work_dir = target_path
        if not is_upload:
            temp_dir = tempfile.mkdtemp()
            import git

            git.Repo.clone_from(target_path, temp_dir, depth=1, single_branch=True, no_checkout=False)
            work_dir = temp_dir

        # Run scanner
        df: pd.DataFrame = scanner.scan_path(work_dir)

        findings = df.to_dict("records") if not df.empty else []

        stats = {
            "total": len(findings),
            "critical": len(
                [f for f in findings if f.get("severity") == "CRITICAL"]
            ),
            "high": len([f for f in findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in findings if f.get("severity") == "MEDIUM"]),
            "low": len([f for f in findings if f.get("severity") == "LOW"]),
        }

        scans_db[scan_id].update(
            {"status": "completed", "findings": findings, "stats": stats}
        )

        # Cleanup cloned repo
        if not is_upload:
            shutil.rmtree(work_dir, ignore_errors=True)

    except Exception as e:
        scans_db[scan_id].update({"status": "failed", "error": str(e)})


@app.get("/api/scans")
def list_scans():
    """Get all scans."""
    return {"scans": list(scans_db.values())}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    """Get a specific scan with findings."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_db[scan_id]


@app.get("/api/scans/{scan_id}/findings/{finding_id}")
def get_finding_detail(scan_id: str, finding_id: int):
    """Get detailed info for a single finding."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scans_db[scan_id]["findings"]
    if finding_id < 0 or finding_id >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")

    return findings[finding_id]


@app.get("/api/scans/{scan_id}/findings/{finding_id}/mitigation")
def get_finding_mitigation(scan_id: str, finding_id: int):
    """Get AI-generated mitigation for a specific finding."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = scans_db[scan_id]["findings"]
    if finding_id < 0 or finding_id >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding = findings[finding_id]
    
    # Generate AI mitigation using the scanner's Qwen model
    try:
        mitigation = scanner.generate_mitigation(
            finding.get("vulnerability", ""),
            finding.get("code_snippet", ""),
            finding.get("cwe_id", ""),
            finding.get("primary_language", "")
        )
        return {"mitigation": mitigation}
    except Exception as e:
        return {"mitigation": f"Error generating mitigation: {str(e)}"}

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    """Delete a scan."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans_db[scan_id]
    return {"message": "Scan deleted"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8082)
