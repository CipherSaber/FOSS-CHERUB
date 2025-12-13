#!/usr/bin/env python3
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import tempfile
import shutil
import uuid
import os
from pathlib import Path
import pandas as pd
import json
import sys

# Add parent directory to path to import from root
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import your scanner and database adapter
from foss_scanner import FOSSCHERUBScanner  # Your scanner class
from db_adapter import DatabaseAdapter

app = FastAPI(title="FOSS-CHERUB API", version="2.0")

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Initialize database adapter (SQLite only)
db_adapter = DatabaseAdapter()

# In-memory store for compatibility (will be replaced gradually)
scans_db: Dict[str, Dict[str, Any]] = {}

# Lazy-load scanner for fast startup
MODEL_PATH = "/workspace/vulnerability-detection-tool/data_processing/merged_model"
scanner = None

def get_scanner():
    """Lazy-load scanner on first use."""
    global scanner
    if scanner is None:
        print("⏳ Loading scanner and AI model...")
        scanner = FOSSCHERUBScanner(None, MODEL_PATH)
        print("✓ Scanner initialized")
    return scanner

@app.on_event("startup")
async def startup_event():
    print("✓ Using SQLite database")
    print("✓ API ready (scanner will load on first scan)")


class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    scan_name: Optional[str] = "Unnamed Scan"
    incremental: bool = True
    since_commit: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class SimilaritySearchRequest(BaseModel):
    query: str
    search_type: str = "vulnerability"  # "vulnerability" or "code"
    limit: int = 10
    threshold: float = 0.7


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
        return {
            "database": "sqlite_only",
            "test_query_results": 0,
            "sample_cve": "CVE-2023-1234 (mock)"
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

    # Store in database
    db_adapter.insert_scan(scan_id, request.repo_url, request.scan_name, "running")
    
    # Keep in-memory for compatibility
    scans_db[scan_id] = {
        "id": scan_id,
        "name": request.scan_name,
        "repo_url": request.repo_url,
        "status": "running",
        "findings": [],
        "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    background_tasks.add_task(run_scan_task, scan_id, request.repo_url, False, request.incremental, request.since_commit, get_scanner)

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

    background_tasks.add_task(run_scan_task, scan_id, str(file_path), True, False, None, get_scanner)  # Uploads are always full scan

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message="File uploaded, scanning...",
    )


def run_scan_task(scan_id: str, target_path: str, is_upload: bool, use_incremental: bool = True, since_commit: Optional[str] = None, scanner_loader=None) -> None:
    """Background task to run the actual scan."""
    try:
        # Get scanner instance (lazy-loaded)
        scanner = scanner_loader() if scanner_loader else get_scanner()
        # Clone Git repo or extract archive
        work_dir = target_path
        if is_upload:
            # Extract archive
            import zipfile
            import tarfile
            extract_dir = tempfile.mkdtemp()
            if target_path.endswith('.zip'):
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif target_path.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(target_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
            work_dir = extract_dir
        else:
            import git
            temp_dir = tempfile.mkdtemp()
            git.Repo.clone_from(target_path, temp_dir, depth=1, single_branch=True, no_checkout=False)
            work_dir = temp_dir

        # Always perform full scan
        print(f"Full scan of directory: {work_dir}")

        # Run scanner
        print(f"Starting fast scan of {work_dir}")
        
        print(f"Full scan of directory: {work_dir}")
        df: pd.DataFrame = scanner.scan_path(work_dir)
        
        print(f"Scan completed. Found {len(df)} findings")
        if not df.empty:
            print(f"Findings columns: {list(df.columns)}")
            print(f"Sample finding: {df.iloc[0].to_dict() if len(df) > 0 else 'None'}")
        else:
            print("No findings detected - this could be due to:")
            print("1. No vulnerabilities in the code")
            print("2. Scanner configuration issues")
            print("3. Missing dependencies (semgrep, model files)")

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

        # Update database
        db_adapter.update_scan_status(scan_id, "completed")
        
        # Store findings in database
        for finding in findings:
            try:
                vuln_name = finding.get("vulnerability", "")
                if not vuln_name or vuln_name.lower() in ['unknown', 'unknown vulnerability', '']:
                    vuln_name = "Security Vulnerability"
                
                db_adapter.insert_finding(
                    scan_id,
                    finding.get("file_path", ""),
                    int(finding.get("line_number", 0)),
                    finding.get("severity", "UNKNOWN"),
                    finding.get("cwe_id", ""),
                    vuln_name,
                    finding.get("code_snippet", ""),
                    finding.get("ai_mitigation", ""),
                    finding.get("corrected_code", ""),
                    finding.get("code_quality_improvements", ""),
                    finding.get("safer_coding_alternatives", ""),
                    finding.get("ast_structure_analysis", ""),
                    finding.get("security_best_practices", ""),
                    finding.get("performance_impact", ""),
                    json.dumps(finding.get("vulnerability_patterns", [])),
                    finding.get("remediation_priority", "medium"),
                    json.dumps(finding.get("code_complexity_metrics", {})),
                    json.dumps(finding.get("compliance_violations", [])),
                    finding.get("business_impact", "")
                )
            except Exception as e:
                print(f"Error storing finding: {e}")
        
        # Update in-memory store with enhanced data
        enhanced_stats = stats.copy()
        enhanced_stats.update({
            "taint_confirmed": len([f for f in findings if "TAINTED SINK" in f.get("taint_flow", "")]),
            "taint_safe": len([f for f in findings if "SINK - safe" in f.get("taint_flow", "")]),
            "with_ai_analysis": len([f for f in findings if f.get("code_analysis")])
        })
        
        scans_db[scan_id].update(
            {"status": "completed", "findings": findings, "stats": enhanced_stats}
        )

        # Cleanup temp directories
        shutil.rmtree(work_dir, ignore_errors=True)
        if is_upload and os.path.exists(target_path):
            os.remove(target_path)  # Remove uploaded file

    except Exception as e:
        print(f"Scan failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        scans_db[scan_id].update({"status": "failed", "error": str(e)})
        db_adapter.update_scan_status(scan_id, "failed")


@app.get("/api/scans")
def list_scans():
    """Get all scans."""
    # Try to load from database first
    try:
        conn = db_adapter.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.scan_id, s.repo_url, s.scan_name, s.status, s.created_at, COUNT(f.id) as findings_count
            FROM scans s
            LEFT JOIN findings f ON s.scan_id = f.scan_id
            GROUP BY s.scan_id, s.repo_url, s.scan_name, s.status, s.created_at
            ORDER BY s.created_at DESC
        """)
        
        db_scans = []
        for row in cursor.fetchall():
            scan_data = {
                "id": row[0],
                "name": row[2],
                "repo_url": row[1],
                "status": row[3],
                "created_at": row[4],
                "stats": {
                    "total": row[5],
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }
            db_scans.append(scan_data)
        
        cursor.close()
        conn.close()
        
        # Merge with in-memory scans
        all_scans = db_scans + list(scans_db.values())
        return {"scans": all_scans}
    except Exception as e:
        print(f"Error loading scans from database: {e}")
        return {"scans": list(scans_db.values())}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    """Get a specific scan with findings."""
    # Try database first
    try:
        scan_data = db_adapter.get_scan(scan_id)
        if scan_data:
            findings = db_adapter.get_findings(scan_id)
            # Map database fields to expected frontend format with enhanced fields
            formatted_findings = []
            for f in findings:
                formatted_finding = {
                    "vulnerability": f.get("description", "Unknown Vulnerability"),
                    "file_path": f.get("file_path", ""),
                    "line_number": f.get("line_number", 0),
                    "severity": f.get("severity", "UNKNOWN"),
                    "cwe_id": f.get("cwe_id", ""),
                    "code_snippet": f.get("code_snippet", ""),
                    "vulnerable_code": f"```\n{f.get('code_snippet', '')}\n```",
                    "ai_mitigation": f.get("ai_mitigation") or "",
                    "corrected_code": f.get("corrected_code") or "",
                    # Enhanced fields from database - ensure they're not None
                    "code_quality_improvements": f.get("code_quality_improvements") or "",
                    "safer_coding_alternatives": f.get("safer_coding_alternatives") or "",
                    "ast_structure_analysis": f.get("ast_structure_analysis") or "",
                    "security_best_practices": f.get("security_best_practices") or "",
                    "performance_impact": f.get("performance_impact") or "",
                    "vulnerability_patterns": f.get("vulnerability_patterns") or [],
                    "remediation_priority": f.get("remediation_priority") or "medium",
                    "code_complexity_metrics": f.get("code_complexity_metrics") or {},
                    "compliance_violations": f.get("compliance_violations") or [],
                    "business_impact": f.get("business_impact") or ""
                }
                formatted_findings.append(formatted_finding)
            
            scan_data['findings'] = formatted_findings
            scan_data['stats'] = {
                "total": len(findings),
                "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                "high": len([f for f in findings if f.get("severity") == "HIGH"]),
                "medium": len([f for f in findings if f.get("severity") == "MEDIUM"]),
                "low": len([f for f in findings if f.get("severity") == "LOW"]),
            }
            return scan_data
    except Exception as e:
        print(f"Error loading scan from database: {e}")
    
    # Fallback to in-memory store
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id].copy()
    
    # The findings already have all enhanced fields from the scanner
    # Just ensure vulnerable_code is formatted
    if 'findings' in scan_data:
        for finding in scan_data['findings']:
            if 'code_snippet' in finding and 'vulnerable_code' not in finding:
                code = finding['code_snippet']
                finding['vulnerable_code'] = f"```{finding.get('primary_language', 'text').lower()}\n{code}\n```"
    
    return scan_data


@app.get("/api/scans/{scan_id}/findings/{finding_id}")
def get_finding_detail(scan_id: str, finding_id: int):
    """Get detailed info for a single finding."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scans_db[scan_id]["findings"]
    if finding_id < 0 or finding_id >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")

    return findings[finding_id]


@app.get("/api/scans/{scan_id}/findings/{finding_id}/analysis")
def get_finding_comprehensive_analysis(scan_id: str, finding_id: int):
    """Get comprehensive AI analysis for a specific finding."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = scans_db[scan_id]["findings"]
    if finding_id < 0 or finding_id >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding = findings[finding_id]
    
    # Generate comprehensive AI analysis using the scanner's Qwen model
    try:
        scanner_instance = get_scanner()
        analysis = scanner_instance.generate_comprehensive_analysis(
            finding.get("vulnerability", ""),
            finding.get("code_snippet", ""),
            finding.get("cwe_id", ""),
            finding.get("primary_language", ""),
            finding.get("taint_flow", ""),
            finding.get("ast_tree", "")
        )
        
        # Add existing data from finding
        result = {
            "finding_id": finding_id,
            "vulnerability": finding.get("vulnerability", ""),
            "cwe_id": finding.get("cwe_id", ""),
            "severity": finding.get("severity", ""),
            "file_path": finding.get("file_path", ""),
            "line_number": finding.get("line_number", ""),
            "code_snippet": finding.get("code_snippet", ""),
            "taint_flow": finding.get("taint_flow", ""),
            "ast_tree": finding.get("ast_tree", ""),
            "code_analysis": analysis.get("code_analysis", ""),
            "ai_mitigation": analysis.get("ai_mitigation", ""),
            "ast_insights": analysis.get("ast_insights", ""),
            "corrected_code": analysis.get("corrected_code", ""),
            "incremental_analysis": analysis.get("incremental_analysis", "")
        }
        
        return result
    except Exception as e:
        return {
            "error": f"Error generating analysis: {str(e)}",
            "finding_id": finding_id,
            "basic_info": {
                "vulnerability": finding.get("vulnerability", ""),
                "cwe_id": finding.get("cwe_id", ""),
                "severity": finding.get("severity", "")
            }
        }

@app.get("/api/scans/{scan_id}/findings/{finding_id}/mitigation")
def get_finding_mitigation(scan_id: str, finding_id: int):
    """Get AI-generated mitigation for a specific finding (backward compatibility)."""
    analysis = get_finding_comprehensive_analysis(scan_id, finding_id)
    if "error" in analysis:
        return {"mitigation": "Mitigation advice unavailable due to analysis error."}
    return {"mitigation": analysis.get("ai_mitigation", "Mitigation advice unavailable.")}

@app.get("/api/cve/search/{cwe_id}")
def search_cve_by_cwe(cwe_id: str, limit: int = 10):
    """Search CVEs by CWE ID"""
    try:
        cves = db_adapter.query_cve_by_cwe(cwe_id, limit)
        cwe_info = db_adapter.get_cwe_info(cwe_id)
        return {
            "cwe_id": cwe_id,
            "cwe_info": cwe_info,
            "related_cves": cves,
            "count": len(cves)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE search failed: {str(e)}")

@app.get("/api/findings/{scan_id}/enriched")
def get_enriched_findings(scan_id: str):
    """Get findings enriched with CVE data"""
    try:
        findings = db_adapter.get_findings(scan_id)
        enriched_findings = [db_adapter.enrich_finding_with_cve(f) for f in findings]
        return {
            "scan_id": scan_id,
            "findings": enriched_findings,
            "count": len(enriched_findings)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Finding enrichment failed: {str(e)}")

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    """Delete a scan."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del scans_db[scan_id]
    return {"message": "Scan deleted"}


@app.post("/api/similarity/search")
def similarity_search(request: SimilaritySearchRequest):
    """Search for similar vulnerabilities or code patterns using vector similarity"""
    try:
        scanner_instance = get_scanner()
        if request.search_type == "vulnerability":
            results = scanner_instance.db_conn.find_similar_vulnerabilities(
                request.query, request.limit, request.threshold
            )
        elif request.search_type == "code":
            results = scanner_instance.db_conn.find_similar_code_patterns(
                request.query, request.limit, request.threshold
            )
        else:
            raise HTTPException(status_code=400, detail="Invalid search_type. Use 'vulnerability' or 'code'")
        
        return {
            "query": request.query,
            "search_type": request.search_type,
            "results": results,
            "count": len(results)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.get("/api/similarity/clusters")
def get_vulnerability_clusters(min_size: int = Query(3, description="Minimum cluster size")):
    """Get vulnerability clusters based on similarity"""
    try:
        scanner_instance = get_scanner()
        clusters = scanner_instance.db_conn.get_vulnerability_clusters(min_size)
        return {
            "clusters": clusters,
            "count": len(clusters)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Clustering failed: {str(e)}")


@app.get("/api/findings/{finding_id}/similar")
def find_similar_to_finding(
    finding_id: int, 
    limit: int = Query(10, description="Maximum number of results"),
    threshold: float = Query(0.7, description="Similarity threshold")
):
    """Find vulnerabilities similar to a specific finding"""
    try:
        # Get the finding details first
        finding = None
        for scan_data in scans_db.values():
            for idx, f in enumerate(scan_data.get("findings", [])):
                if idx == finding_id:
                    finding = f
                    break
            if finding:
                break
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Search for similar vulnerabilities
        query_text = finding.get("vulnerability", "")
        scanner_instance = get_scanner()
        results = scanner_instance.db_conn.find_similar_vulnerabilities(query_text, limit, threshold)
        
        return {
            "original_finding": finding,
            "similar_findings": results,
            "count": len(results)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Similarity search failed: {str(e)}")




@app.get("/api/scans/{scan_id}/enhanced")
def get_enhanced_scan_results(scan_id: str):
    """Get scan results with enhanced AI analysis sections."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id].copy()
    findings = scan_data.get("findings", [])
    
    # Enhance findings with structured analysis sections
    enhanced_findings = []
    for i, finding in enumerate(findings):
        enhanced_finding = finding.copy()
        
        # Format vulnerable code section
        if 'code_snippet' in enhanced_finding:
            code = enhanced_finding['code_snippet']
            lang = enhanced_finding.get('primary_language', 'text').lower()
            enhanced_finding['vulnerable_code'] = f"```{lang}\n{code}\n```"
        
        # Ensure all AI analysis sections are present
        enhanced_finding["code_analysis"] = enhanced_finding.get("code_analysis", "Enhanced analysis not available for this finding.")
        enhanced_finding["ai_mitigation"] = enhanced_finding.get("ai_mitigation", "Mitigation advice not available for this finding.")
        enhanced_finding["ast_insights"] = enhanced_finding.get("ast_insights", "AST insights not available for this finding.")
        enhanced_finding["corrected_code"] = enhanced_finding.get("corrected_code", "Corrected code example not available.")
        enhanced_finding["incremental_analysis"] = enhanced_finding.get("incremental_analysis", "Incremental analysis not available.")
        
        # Add AST tree as formatted code block
        if 'ast_tree' in enhanced_finding:
            ast_tree = enhanced_finding['ast_tree']
            enhanced_finding['ast_structure'] = f"```\n{ast_tree}\n```"
        
        # Add taint flow information
        enhanced_finding['taint_analysis'] = {
            'flow': enhanced_finding.get('taint_flow', 'No taint analysis available'),
            'confidence': enhanced_finding.get('taint_confidence', 'unknown')
        }
        
        enhanced_findings.append(enhanced_finding)
    
    scan_data["findings"] = enhanced_findings
    return scan_data

@app.get("/api/scans/{scan_id}/taint-summary")
def get_taint_analysis_summary(scan_id: str):
    """Get taint analysis summary for a scan."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = scans_db[scan_id].get("findings", [])
    
    taint_confirmed = len([f for f in findings if "TAINTED SINK" in f.get("taint_flow", "")])
    taint_safe = len([f for f in findings if "SINK - safe" in f.get("taint_flow", "")])
    high_confidence = len([f for f in findings if f.get("taint_confidence") == "high"])
    medium_confidence = len([f for f in findings if f.get("taint_confidence") == "medium"])
    low_confidence = len([f for f in findings if f.get("taint_confidence") == "low"])
    
    return {
        "scan_id": scan_id,
        "total_findings": len(findings),
        "taint_analysis": {
            "confirmed_tainted": taint_confirmed,
            "safe_sinks": taint_safe,
            "confidence_levels": {
                "high": high_confidence,
                "medium": medium_confidence,
                "low": low_confidence
            }
        },
        "analysis_coverage": {
            "with_taint_flow": len([f for f in findings if f.get("taint_flow") and "No taint analysis" not in f.get("taint_flow", "")]),
            "with_ast_tree": len([f for f in findings if f.get("ast_tree") and "No AST available" not in f.get("ast_tree", "")]),
            "with_ai_analysis": len([f for f in findings if f.get("code_analysis")])
        }
    }

@app.get("/api/analysis/sections")
def get_available_analysis_sections():
    """Get information about available analysis sections."""
    return {
        "sections": {
            "code_analysis": {
                "description": "Detailed analysis of vulnerable code patterns and security implications",
                "available": True
            },
            "ai_mitigation": {
                "description": "AI-generated mitigation strategies with priority levels",
                "available": True
            },
            "ast_insights": {
                "description": "Abstract Syntax Tree analysis showing vulnerability structure",
                "available": True
            },
            "corrected_code": {
                "description": "Secure code examples with detailed explanations",
                "available": True
            },
            "incremental_analysis": {
                "description": "Recommendations for preventing similar issues in future changes",
                "available": True
            },
            "taint_flow": {
                "description": "Data flow analysis from sources to sinks",
                "available": True
            }
        },
        "features": {
            "multi_language_support": ["Python", "JavaScript", "Java", "C", "C++", "PHP", "Go", "Ruby", "Rust"],
            "taint_tracking": True,
            "ast_analysis": True,
            "incremental_scanning": True,
            "ai_powered_insights": True
        }
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8082)
