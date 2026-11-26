import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from pydantic import BaseModel
import uvicorn

from security import decrypt_secret, verify_password, issue_token, verify_token

load_dotenv()

app = FastAPI(title="BDI Zero-Knowledge Session Broker")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)


@contextmanager
def get_db():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        sslmode=os.getenv("DB_SSLMODE", "require"),
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def log_event(conn, employee_id, employee_user, client_code, status, ip, machine, details=""):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO bdi_access_logs
                (employee_id, employee_user, client_code, status, ip_address, machine_name, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (employee_id, employee_user, client_code, status, ip, machine, details),
        )


def get_current_employee(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization token.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = verify_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, full_name, allowed_clients, is_active FROM bdi_employees WHERE id = %s",
                (claims["eid"],),
            )
            emp = cur.fetchone()

    if not emp or not emp["is_active"]:
        raise HTTPException(status_code=403, detail="Account disabled or revoked.")
    return emp


class LoginRequest(BaseModel):
    username: str
    password: str
    machine_name: str = ""


class LaunchRequest(BaseModel):
    client_code: str
    machine_name: str = ""


def rtpos_login_cookies(login_url: str, username: str, password: str) -> list[dict]:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    resp = session.get(login_url, timeout=15)
    soup = BeautifulSoup(resp.text, "html.parser")
    sec_input = soup.find("input", {"name": "secSessionID"})
    if not sec_input:
        raise ConnectionError("Could not reach BDI login page.")

    payload = {
        "secSessionID": sec_input["value"],
        "secUserID": username,
        "secPassword": password,
        "secSaveCookie": "1",
    }
    login_resp = session.post(login_url, data=payload, timeout=15)
    if "secUserID" in login_resp.text:
        raise PermissionError("BDI rejected the vaulted credentials.")

    return [
        {
            "name": c.name,
            "value": c.value,
            "path": c.path or "/",
            "secure": bool(c.secure),
        }
        for c in session.cookies
    ]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/login")
def employee_login(body: LoginRequest, request: Request):
    ip = get_client_ip(request)
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, username, full_name, password_hash, allowed_clients, is_active
                FROM bdi_employees WHERE LOWER(username) = LOWER(%s)
                """,
                (body.username.strip(),),
            )
            emp = cur.fetchone()

            if not emp or not verify_password(body.password, emp["password_hash"]):
                log_event(conn, emp["id"] if emp else None, body.username, None, "DENIED", ip, body.machine_name, "Invalid password")
                raise HTTPException(status_code=401, detail="Invalid username or password.")

            if not emp["is_active"]:
                log_event(conn, emp["id"], emp["username"], None, "DENIED", ip, body.machine_name, "Account revoked")
                raise HTTPException(status_code=403, detail="Your account has been disabled.")

            cur.execute("UPDATE bdi_employees SET last_login_at = NOW() WHERE id = %s", (emp["id"],))

            # Filter allowed_clients against currently active clients in DB
            cur.execute(
                """
                SELECT client_code, display_name
                FROM bdi_clients
                WHERE is_active = TRUE AND client_code = ANY(%s)
                ORDER BY client_code
                """,
                (emp["allowed_clients"],),
            )
            clients = cur.fetchall()

    token = issue_token(emp["id"], emp["username"])
    return {
        "token": token,
        "full_name": emp["full_name"],
        "clients": clients,
    }


@app.post("/api/portal/session")
def create_portal_session(body: LaunchRequest, request: Request, emp=Depends(get_current_employee)):
    ip = get_client_ip(request)
    code = body.client_code.strip().upper()

    with get_db() as conn:
        if code not in [c.upper() for c in emp["allowed_clients"]]:
            log_event(conn, emp["id"], emp["username"], code, "DENIED", ip, body.machine_name, "Client not permitted")
            raise HTTPException(status_code=403, detail=f"You are not authorized for {code}.")

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT client_code, login_url, username_enc, password_enc FROM bdi_clients WHERE UPPER(client_code) = %s AND is_active = TRUE",
                (code,),
            )
            client = cur.fetchone()

        if not client:
            raise HTTPException(status_code=404, detail=f"Client '{code}' not configured or inactive.")

        try:
            bdi_user = decrypt_secret(client["username_enc"])
            bdi_pass = decrypt_secret(client["password_enc"])
            cookies = rtpos_login_cookies(client["login_url"], bdi_user, bdi_pass)
        except Exception as exc:
            log_event(conn, emp["id"], emp["username"], code, "FAILED", ip, body.machine_name, str(exc))
            raise HTTPException(status_code=502, detail=f"BDI authentication failed: {exc}")

        log_event(conn, emp["id"], emp["username"], code, "SUCCESS", ip, body.machine_name, "Session issued")

    return {
        "login_url": client["login_url"],
        "user_agent": USER_AGENT,
        "cookies": cookies,
    }


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "5000")))