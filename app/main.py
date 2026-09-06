"""Orders API — deliberately vulnerable training application.

======================================================================
THIS APPLICATION CONTAINS INTENTIONAL SECURITY FLAWS.
It exists to generate findings in GitHub code scanning. Do not deploy it,
do not reuse its code, and keep the repository clearly labelled as a lab.
======================================================================

Expected CodeQL rules in this module:
  py/reflective-xss (CWE-79)
  py/stack-trace-exposure (CWE-209)
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from app import auth, db, importer, integrations, reports

app = FastAPI(title="Orders API (LAB — intentionally vulnerable)", version="0.4.2")


@app.on_event("startup")
def startup() -> None:
    db.init_schema()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


# --- VULN 17: reflected cross-site scripting (CWE-79) ---------------------
# CodeQL: py/reflective-xss
@app.get("/search", response_class=HTMLResponse)
def search(customer: str) -> str:
    rows = db.find_orders_by_customer(customer)
    return f"""
        <html><body>
          <h1>Results for {customer}</h1>
          <p>{len(rows)} order(s) found.</p>
        </body></html>
    """


@app.get("/orders")
def list_orders(sort: str = "id", direction: str = "ASC"):
    return db.list_orders_sorted(sort, direction)


@app.post("/login")
def login(username: str, password: str):
    user = auth.authenticate(username, password)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"session": auth.sign_session(user["username"]), "role": user["role"]}


@app.get("/reports/{name}")
def get_report(name: str):
    # --- VULN 18: stack trace exposure (CWE-209) --------------------------
    # CodeQL: py/stack-trace-exposure
    try:
        return {"content": reports.read_report(name)}
    except Exception as exc:  # noqa: BLE001
        import traceback

        return JSONResponse(
            status_code=500,
            content={"error": str(exc), "trace": traceback.format_exc()},
        )


@app.post("/reports/{name}/pdf")
def make_pdf(name: str):
    return {"path": reports.convert_report_to_pdf(name)}


@app.post("/import/cart")
def import_cart(blob: str):
    return {"cart": str(importer.load_saved_cart(blob))}


@app.post("/import/feed")
def import_feed(xml: str):
    root = importer.parse_partner_feed(xml)
    return {"root_tag": root.tag}


@app.get("/partner/document")
def partner_document(url: str):
    return {"body": integrations.fetch_partner_document(url)}


if __name__ == "__main__":
    import uvicorn

    # --- VULN 19: binds every interface (CWE-668) -------------------------
    # CodeQL: py/bind-socket-all-network-interfaces (low severity — a good
    # candidate for a "risk accepted" dismissal during triage practice).
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104
