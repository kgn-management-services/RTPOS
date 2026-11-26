import os
import sys
import secrets
import getpass
import psycopg2
from pathlib import Path
from dotenv import load_dotenv
from cryptography.fernet import Fernet

from security import encrypt_secret, hash_password

load_dotenv()


def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        sslmode=os.getenv("DB_SSLMODE", "require"),
    )


def cmd_generate_keys():
    print("Copy these into your server .env file (keep them secret and backed up):\n")
    print(f"VAULT_MASTER_KEY={Fernet.generate_key().decode()}")
    print(f"TOKEN_SECRET={secrets.token_hex(32)}")


def cmd_init_db():
    sql = Path("schema.sql").read_text(encoding="utf-8")
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(sql)
    print("Tables created/verified in database:", os.getenv("DB_NAME"))


def cmd_upsert_client():
    code = input("Client code (e.g. AMPCS, P4ALL, PRIME.T): ").strip().upper()
    name = input(f"Display name [{code}]: ").strip() or code
    url = input("Login URL [https://myrtpos.com/newbdi/index.fwx]: ").strip() or "https://myrtpos.com/newbdi/index.fwx"
    bdi_user = input("BDI Username: ").strip()
    bdi_pass = input("BDI Password: ").strip()

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO bdi_clients (client_code, display_name, login_url, username_enc, password_enc, is_active, updated_at)
            VALUES (%s, %s, %s, %s, %s, TRUE, NOW())
            ON CONFLICT (client_code) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                login_url    = EXCLUDED.login_url,
                username_enc = EXCLUDED.username_enc,
                password_enc = EXCLUDED.password_enc,
                is_active    = TRUE,
                updated_at   = NOW()
            """,
            (code, name, url, encrypt_secret(bdi_user), encrypt_secret(bdi_pass)),
        )
    print(f"Encrypted credentials saved for client '{code}'.")


def cmd_upsert_employee():
    username = input("Employee login username (e.g. rasool): ").strip().lower()
    full_name = input("Full name: ").strip()
    password = input("Employee password: ").strip()
    clients_raw = input("Allowed clients (comma-separated, e.g. AMPCS,P4ALL,PRIME.T): ").strip()
    allowed = [c.strip().upper() for c in clients_raw.split(",") if c.strip()]

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO bdi_employees (username, full_name, password_hash, allowed_clients, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
            ON CONFLICT (username) DO UPDATE SET
                full_name       = EXCLUDED.full_name,
                password_hash   = EXCLUDED.password_hash,
                allowed_clients = EXCLUDED.allowed_clients,
                is_active       = TRUE
            """,
            (username, full_name, hash_password(password), allowed),
        )
    print(f"Employee '{username}' saved with access to: {allowed}")


def cmd_revoke_employee():
    username = input("Employee username to disable: ").strip().lower()
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE bdi_employees SET is_active = FALSE WHERE LOWER(username) = %s", (username,))
        if cur.rowcount:
            print(f"Access revoked immediately for '{username}'.")
        else:
            print(f"No employee found matching '{username}'.")


COMMANDS = {
    "generate-keys": cmd_generate_keys,
    "init-db": cmd_init_db,
    "add-client": cmd_upsert_client,
    "add-employee": cmd_upsert_employee,
    "revoke-employee": cmd_revoke_employee,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python admin_cli.py [generate-keys | init-db | add-client | add-employee | revoke-employee]")
        sys.exit(1)
    COMMANDS[sys.argv[1]]()