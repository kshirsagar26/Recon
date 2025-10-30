import sublist3r
import requests
import subprocess
import os
from pathlib import Path

def run_sublist3r(domain):
    try:
        ports = None
        enable_bruteforce = False
        engines = None
        result = sublist3r.main(
            domain, 40, None,
            ports=ports,
            silent=True,
            verbose=False,
            enable_bruteforce=enable_bruteforce,
            engines=engines
        )
        return sorted(set(result))
    except Exception:
        return []

def run_crtsh(domain):
    try:
        response = requests.get(f'https://crt.sh/?q=%25.{domain}&output=json', timeout=10)
        if response.ok:
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        if sub.endswith(domain):
                            subdomains.add(sub.strip())
            return sorted(subdomains)
        return []
    except Exception:
        return []

def run_subfinder(domain):
    try:
        # Get the project root directory (where subfinder.exe is located)
        project_root = Path(__file__).parent.parent.parent.parent
        subfinder_path = project_root / 'subfinder.exe'
        
        # Try local subfinder.exe first, fall back to system PATH
        if subfinder_path.exists():
            cmd = [str(subfinder_path), '-d', domain, '-silent']
        else:
            cmd = ['subfinder', '-d', domain, '-silent']
        
        # Run subfinder command
        output = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=120
        )
        subdomains = output.decode().splitlines()
        return sorted(set(subdomains))
    except FileNotFoundError:
        # Subfinder not found, return empty list
        return []
    except Exception:
        return []

def enumerate_subdomains(domain: str):
    sublist3r_results = run_sublist3r(domain)
    crtsh_results = run_crtsh(domain)
    subfinder_results = run_subfinder(domain)
    all_unique = sorted(set(sublist3r_results) | set(crtsh_results) | set(subfinder_results))
    return {
        "sublist3r_results": {
            "count": len(sublist3r_results),
            "subdomains": sublist3r_results
        },
        "crtsh_results": {
            "count": len(crtsh_results),
            "subdomains": crtsh_results
        },
        "subfinder_results": {
            "count": len(subfinder_results),
            "subdomains": subfinder_results
        },
        "all_unique_combined": {
            "count": len(all_unique),
            "subdomains": all_unique
        }
    }
