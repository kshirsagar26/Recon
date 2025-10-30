from fastapi import FastAPI
from app.modules.subdomain_enum.engine import enumerate_subdomains

app = FastAPI(
    title="Recon Backend",
    description="Backend for reconnaissance framework with modular scanning."
)

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
