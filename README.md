# Recon Framework Prototype

This project is a modular backend for reconnaissance automation.  
**Current module:** Subdomain Enumeration (Prototype)

## Main Features

- FastAPI backend
- Subdomain enumeration via `/subdomains/{domain}` endpoint

## Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run server:**
   ```bash
   uvicorn app.main:app --reload
   ```

3. **Example API Call:**
   ```
   GET http://localhost:8000/subdomains/example.com
   ```

