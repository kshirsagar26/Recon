from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from app.modules.subdomain_enum.engine import enumerate_subdomains
from app.modules.port_scan.engine import PortScanner, scan_subdomains
from app.modules.port_scan.benchmark import BenchmarkSuite, compare_hybrid_vs_single
from app.modules.port_scan.metrics import MetricsCollector, ThesisComparison
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


# Port Scanning Endpoints

@app.post("/api/port-scan/single")
async def scan_single_host(host_data: Dict[str, Any]):
    """
    Scan a single host for open ports.
    
    Request body:
    {
        "host": "example.com or IP",
        "ports": [80, 443, 8080],  # Optional, defaults to common ports
        "technique": "tcp_connect"  # 'tcp_connect', 'syn', 'udp'
    }
    """
    host = host_data.get("host", "").strip()
    ports = host_data.get("ports", [])
    technique = host_data.get("technique", "tcp_connect")
    
    if not host:
        return {"error": "Host is required"}
    
    try:
        scanner = PortScanner(timeout=3.0, max_workers=50)
        
        if ports:
            results, metrics = await scanner.scan_port_range(
                host,
                start_port=min(ports),
                end_port=max(ports),
                use_common_ports=False,
                technique=technique
            )
        else:
            results, metrics = await scanner.scan_common_ports(host)
        
        return {
            "host": host,
            "results": [
                {
                    "port": r.port,
                    "status": r.status,
                    "service": r.service,
                    "version": r.version,
                    "banner": r.banner,
                    "response_time": r.response_time
                }
                for r in results
            ],
            "metrics": {
                "total_ports_scanned": metrics.total_ports_scanned,
                "open_ports_found": metrics.open_ports_found,
                "closed_ports": metrics.closed_ports,
                "filtered_ports": metrics.filtered_ports,
                "total_time": metrics.total_time,
                "ports_per_second": metrics.ports_per_second,
                "average_response_time": metrics.average_response_time,
                "concurrent_connections": metrics.concurrent_connections
            }
        }
    
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/port-scan/subdomains")
async def scan_subdomains_ports(scan_data: Dict[str, Any]):
    """
    Scan multiple subdomains for open ports.
    
    Request body:
    {
        "subdomains": ["www.example.com", "api.example.com"],
        "ports": [80, 443, 8080],  # Optional
        "technique": "tcp_connect"
    }
    """
    subdomains = scan_data.get("subdomains", [])
    ports = scan_data.get("ports", [])
    technique = scan_data.get("technique", "tcp_connect")
    
    if not subdomains:
        return {"error": "Subdomains list is required"}
    
    try:
        results = await scan_subdomains(
            subdomains,
            ports=ports if ports else None,
            technique=technique
        )
        return results
    
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/benchmark")
async def run_benchmark(target: str = "127.0.0.1"):
    """
    Run comprehensive benchmark comparing port scanning tools.
    
    Query params:
    - target: Host to benchmark against (default: 127.0.0.1)
    """
    try:
        benchmark = BenchmarkSuite(target_host=target)
        results = await benchmark.run_comprehensive_benchmark()
        return results
    
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/thesis/hybrid-comparison")
async def hybrid_vs_single(target: str = "127.0.0.1"):
    """
    Compare hybrid reconnaissance vs single method scanning.
    
    This endpoint validates the thesis:
    "Hybrid reconnaissance (passive + active) yields better results than single method"
    
    Query params:
    - target: Host to scan (default: 127.0.0.1)
    """
    try:
        comparison = await compare_hybrid_vs_single(target)
        return comparison
    
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/thesis/metrics")
def get_thesis_metrics():
    """
    Get summary metrics for thesis comparison.
    
    Returns metrics formatted for research papers and thesis documentation.
    """
    return {
        "thesis_question": (
            "Can hybrid reconnaissance (combining passive and active techniques) "
            "yield better results than using a single method?"
        ),
        "key_metrics": {
            "speed": "Ports per second scanned",
            "accuracy": "Precision, Recall, F1-Score",
            "coverage": "Unique services discovered",
            "efficiency": "Accuracy per unit time",
            "stealthiness": "Detection probability"
        },
        "endpoints": {
            "single_host_scan": "POST /api/port-scan/single",
            "multi_subdomain_scan": "POST /api/port-scan/subdomains",
            "run_benchmark": "GET /api/benchmark?target=<host>",
            "hybrid_comparison": "GET /api/thesis/hybrid-comparison?target=<host>"
        },
        "documentation": {
            "custom_scanner": "Efficient async-based port scanner with service detection",
            "metrics": "Comprehensive metrics for thesis research",
            "benchmark": "Comparison with Nmap, Masscan, and other tools"
        }
    }


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
