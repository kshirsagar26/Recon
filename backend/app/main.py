from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.modules.subdomain_enum.engine import enumerate_subdomains
from typing import List, Dict, Any
import json
import asyncio

app = FastAPI(
    title="Recon Backend",
    description="Backend for reconnaissance framework with modular scanning."
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results (in production, use a database)
scan_results: List[Dict[str, Any]] = []
scan_progress: Dict[str, Any] = {
    "portScanning": 0,
    "currentTarget": "",
    "portsScanned": 0,
    "totalPorts": 10000,
}

@app.get("/")
def read_root():
    return {"message": "Recon backend running"}

@app.get("/subdomains/{domain}")
def get_subdomains(domain: str):
    """
    API endpoint to enumerate subdomains for a given domain.
    """
    result = enumerate_subdomains(domain)
    return {"domain": domain, "subdomains": result}


# Dashboard API endpoints
@app.get("/api/scans")
async def get_scans(root_domain: str = None):
    """Get all scan results, optionally filtered by root domain."""
    if root_domain:
        # Filter by root domain
        filtered = [r for r in scan_results if r.get("rootDomain") == root_domain]
        return {"results": filtered}
    else:
        # Return only results for the current target domain (most recent scan)
        current_target = scan_progress.get("currentTarget", "")
        if current_target:
            # Show only results for the current target
            current_results = [r for r in scan_results if r.get("rootDomain") == current_target]
            return {"results": current_results}
        return {"results": scan_results}


@app.get("/api/stats")
async def get_stats():
    """Get summary statistics."""
    # Each scan result represents one subdomain
    total_subdomains = len(scan_results)
    
    # Count vulnerabilities (Critical and Warning status)
    total_vulnerabilities = sum(
        1 for scan in scan_results 
        if scan.get("status") in ["Critical", "Warning"]
    )
    
    # Count unique root domains scanned
    unique_root_domains = len(set(
        scan.get("rootDomain", "") for scan in scan_results if scan.get("rootDomain")
    ))
    
    # For active IPs, we can estimate based on unique domains (each subdomain = potential IP)
    # Or count unique domains as active IPs
    unique_ips = total_subdomains  # Each subdomain could have an IP
    
    return {
        "subdomains": total_subdomains,
        "vulnerabilities": total_vulnerabilities,
        "activeIPs": unique_ips,
        "totalScans": unique_root_domains if unique_root_domains > 0 else (1 if total_subdomains > 0 else 0),
    }


@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    """Get vulnerability statistics by severity."""
    critical = sum(1 for scan in scan_results if scan.get("status") == "Critical")
    warning = sum(1 for scan in scan_results if scan.get("status") == "Warning")
    safe = sum(1 for scan in scan_results if scan.get("status") == "Safe")
    
    # Estimate distribution (in production, calculate from actual vulnerability data)
    return {
        "critical": critical,
        "high": max(0, warning - critical),
        "medium": max(0, len(scan_results) - critical - warning - safe) // 2,
        "low": max(0, len(scan_results) - critical - warning - safe) // 2,
        "info": safe,
    }


@app.get("/api/scan-progress")
async def get_scan_progress():
    """Get current scan progress."""
    return scan_progress


@app.post("/api/scans/start")
async def start_scan(domain_data: Dict[str, str]):
    """Start a new scan for a domain."""
    domain = domain_data.get("domain", "")
    if not domain:
        return {"error": "Domain is required"}
    
    # Normalize domain (remove www. and http/https)
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "").strip()
    
    # Update progress
    scan_progress["currentTarget"] = domain
    scan_progress["portScanning"] = 0
    scan_progress["portsScanned"] = 0
    
    # Clear ALL previous results to show only the current scan
    scan_results.clear()
    
    # Run subdomain enumeration
    result = enumerate_subdomains(domain)
    
    # Get all enumerated subdomains
    all_subdomains = result.get("all_unique_combined", {}).get("subdomains", [])
    potential_takeovers = result.get("potential_takeovers", [])
    
    # Create individual scan result entries for each subdomain
    base_id = len(scan_results)
    
    # If no subdomains found, create at least one entry for the main domain
    if not all_subdomains:
        scan_result = {
            "id": str(base_id + 1),
            "domain": domain,
            "rootDomain": domain,  # Track the root domain
            "port": 443,
            "vulnerability": "No Subdomains Found",
            "cveData": "N/A",
            "status": "Safe",
        }
        scan_results.append(scan_result)
    else:
        # Create an entry for each enumerated subdomain
        for idx, subdomain in enumerate(all_subdomains):
            # Determine if this subdomain has takeover vulnerability
            has_takeover = subdomain in potential_takeovers
            
            # Default values
            vulnerability = "None Detected"
            cve_data = "N/A"
            status = "Safe"
            port = 443  # Default port
            
            # Check for takeover
            if has_takeover:
                vulnerability = "Potential Subdomain Takeover"
                cve_data = "CVE-SUBDOMAIN-TAKEOVER"
                status = "Critical"
            else:
                # Check common ports/services
                if "api" in subdomain.lower():
                    port = 443
                elif "www" in subdomain.lower():
                    port = 443
                elif "mail" in subdomain.lower() or "smtp" in subdomain.lower():
                    port = 25
                    vulnerability = "Mail Server"
                    status = "Warning"
                elif "ftp" in subdomain.lower():
                    port = 21
                    vulnerability = "FTP Service"
                    status = "Warning"
                elif "admin" in subdomain.lower() or "dashboard" in subdomain.lower():
                    port = 443
                    vulnerability = "Admin Interface"
                    status = "Warning"
            
            scan_result = {
                "id": str(base_id + idx + 1),
                "domain": subdomain,
                "rootDomain": domain,  # Track the root domain
                "port": port,
                "vulnerability": vulnerability,
                "cveData": cve_data,
                "status": status,
            }
            scan_results.append(scan_result)
    
    # Update scan progress
    scan_progress["portScanning"] = 100
    scan_progress["portsScanned"] = scan_progress["totalPorts"]
    
    return {
        "message": "Scan completed",
        "scan_id": str(base_id + 1),
        "subdomains_found": len(all_subdomains),
        "root_domain": domain,
        "total_results": len([r for r in scan_results if r.get("rootDomain") == domain])
    }


@app.get("/api/search")
async def search_scans(query: str):
    """Search scan results."""
    query_lower = query.lower()
    filtered = [
        scan for scan in scan_results
        if query_lower in scan.get("domain", "").lower()
        or query_lower in scan.get("vulnerability", "").lower()
        or query_lower in scan.get("cveData", "").lower()
    ]
    return {"results": filtered}


@app.websocket("/ws/scan-progress")
async def websocket_scan_progress(websocket: WebSocket):
    """WebSocket endpoint for real-time scan progress updates."""
    await websocket.accept()
    try:
        while True:
            # Send current progress
            await websocket.send_json(scan_progress)
            await asyncio.sleep(2)  # Update every 2 seconds
    except WebSocketDisconnect:
        pass
