import sys
import socket
import subprocess
import requests

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QComboBox, QPushButton, QFrame, QMessageBox,
    QStackedWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings

from selenium import webdriver
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService

# Point this to your live FastAPI server (use HTTPS in production)
API_BASE_URL = "http://127.0.0.1:5000"

STYLESHEET = """
QMainWindow, QWidget#Central {
    background: #080D14;
    color: #E2E8F0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}
#Title { color: #E2E8F0; font-size: 20px; font-weight: 700; }
#Subtitle { color: #8295AD; font-size: 10px; font-weight: 700; letter-spacing: 1.4px; }
#Card {
    background: #121926;
    border: 1px solid #283852;
    border-radius: 10px;
}
#InputLabel { color: #8295AD; font-size: 12px; font-weight: 600; }
QLineEdit, QComboBox {
    background: #1A2436;
    color: #FFFFFF;
    border: 1px solid #283852;
    border-radius: 7px;
    padding: 8px 12px;
    min-height: 22px;
    font-size: 13px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #4A8CF6; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background: #1A2436;
    color: #FFFFFF;
    selection-background-color: #4A8CF6;
    border: 1px solid #283852;
}
#PrimaryButton {
    background: #4A8CF6;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 11px 14px;
    font-size: 13px;
    font-weight: 700;
}
#PrimaryButton:hover { background: #6B9FFA; }
#PrimaryButton:disabled { background: #283852; color: #8295AD; }
#SecondaryButton {
    background: #1A2436;
    color: #8295AD;
    border: 1px solid #283852;
    border-radius: 7px;
    padding: 7px 12px;
    font-size: 12px;
    font-weight: 600;
}
#SecondaryButton:hover { color: #E2E8F0; border-color: #4A8CF6; }
#StatusLabel { color: #8295AD; font-size: 11px; font-family: Consolas, monospace; }
"""


class LaunchWorker(QThread):
    status_changed = pyqtSignal(str)
    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, token: str, client_code: str):
        super().__init__()
        self.token = token
        self.client_code = client_code

    def run(self):
        try:
            self.status_changed.emit(f"Requesting secure session for {self.client_code}...")
            resp = requests.post(
                f"{API_BASE_URL}/api/portal/session",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"client_code": self.client_code, "machine_name": socket.gethostname()},
                timeout=25,
            )
            if resp.status_code != 200:
                detail = resp.json().get("detail", resp.text)
                raise RuntimeError(detail)

            data = resp.json()
            login_url = data["login_url"]
            cookies = data["cookies"]
            user_agent = data["user_agent"]

            self.status_changed.emit("Launching Edge with injected session...")
            options = EdgeOptions()
            options.add_experimental_option("detach", True)
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("prefs", {
                "credentials_enable_service": False,
                "profile.password_manager_enabled": False,
            })
            options.add_argument(f"--user-agent={user_agent}")
            options.add_argument("--start-maximized")

            service = EdgeService()
            if sys.platform == "win32":
                service.creation_flags = subprocess.CREATE_NO_WINDOW

            driver = webdriver.Edge(service=service, options=options)
            driver.get(login_url)
            driver.delete_all_cookies()

            for c in cookies:
                try:
                    driver.add_cookie(c)
                except Exception:
                    pass

            driver.get(login_url)
            self.finished_ok.emit(f"{self.client_code} opened and authenticated.")
        except Exception as exc:
            self.failed.emit(str(exc))


class PortalLauncher(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BDI Portal Launcher")
        self.setFixedSize(410, 320)

        self.settings = QSettings("InferiaTools", "BDIPortalLauncher")
        self.token = None
        self.worker = None

        central = QWidget(objectName="Central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 20, 20, 16)
        root.setSpacing(14)

        header = QVBoxLayout()
        header.setSpacing(2)
        header.addWidget(QLabel("BDI Portal Launcher", objectName="Title"))
        header.addWidget(QLabel("CENTRALIZED ZERO-KNOWLEDGE ACCESS", objectName="Subtitle"))
        root.addLayout(header)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_login_page())
        self.stack.addWidget(self._build_portal_page())
        root.addWidget(self.stack, 1)

        self.status_lbl = QLabel("Sign in with your employee credentials.", objectName="StatusLabel")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self.status_lbl)

        self.setStyleSheet(STYLESHEET)

    def _build_login_page(self):
        card = QFrame(objectName="Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)

        lay.addWidget(QLabel("Employee Username", objectName="InputLabel"))
        self.user_input = QLineEdit(self.settings.value("last_user", ""))
        self.user_input.setPlaceholderText("Enter your username")
        lay.addWidget(self.user_input)

        lay.addWidget(QLabel("Password", objectName="InputLabel"))
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("Enter your password")
        self.pass_input.returnPressed.connect(self.handle_login)
        lay.addWidget(self.pass_input)

        self.login_btn = QPushButton("Sign In")
        self.login_btn.setObjectName("PrimaryButton")
        self.login_btn.clicked.connect(self.handle_login)
        lay.addWidget(self.login_btn)
        return card

    def _build_portal_page(self):
        card = QFrame(objectName="Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(12)

        top = QHBoxLayout()
        self.welcome_lbl = QLabel("Signed in", objectName="InputLabel")
        signout_btn = QPushButton("Sign Out")
        signout_btn.setObjectName("SecondaryButton")
        signout_btn.clicked.connect(self.handle_signout)
        top.addWidget(self.welcome_lbl)
        top.addStretch()
        top.addWidget(signout_btn)
        lay.addLayout(top)

        lay.addWidget(QLabel("Select Client", objectName="InputLabel"))
        self.client_cb = QComboBox()
        lay.addWidget(self.client_cb)

        self.launch_btn = QPushButton("Open BDI Portal")
        self.launch_btn.setObjectName("PrimaryButton")
        self.launch_btn.clicked.connect(self.handle_launch)
        lay.addWidget(self.launch_btn)
        lay.addStretch()
        return card

    def handle_login(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Missing Fields", "Enter both username and password.")
            return

        self.login_btn.setEnabled(False)
        self.status_lbl.setText("Authenticating...")
        QApplication.processEvents()

        try:
            resp = requests.post(
                f"{API_BASE_URL}/api/auth/login",
                json={"username": username, "password": password, "machine_name": socket.gethostname()},
                timeout=15,
            )
            if resp.status_code != 200:
                raise RuntimeError(resp.json().get("detail", "Login failed."))

            data = resp.json()
            self.token = data["token"]
            self.settings.setValue("last_user", username)
            self.pass_input.clear()

            self.client_cb.clear()
            for c in data["clients"]:
                self.client_cb.addItem(c["display_name"], c["client_code"])

            if self.client_cb.count() == 0:
                raise RuntimeError("No clients are assigned to your account.")

            self.welcome_lbl.setText(f"Operator: {data['full_name']}")
            self.stack.setCurrentIndex(1)
            self.status_lbl.setText("Ready. Select a client to launch.")
        except Exception as exc:
            self.status_lbl.setText("Authentication failed.")
            QMessageBox.critical(self, "Sign-In Error", str(exc))
        finally:
            self.login_btn.setEnabled(True)

    def handle_signout(self):
        self.token = None
        self.stack.setCurrentIndex(0)
        self.status_lbl.setText("Signed out.")

    def handle_launch(self):
        client_code = self.client_cb.currentData()
        self.launch_btn.setEnabled(False)
        self.launch_btn.setText(f"Opening {client_code}...")

        self.worker = LaunchWorker(self.token, client_code)
        self.worker.status_changed.connect(self.status_lbl.setText)
        self.worker.finished_ok.connect(self.on_launch_ok)
        self.worker.failed.connect(self.on_launch_fail)
        self.worker.start()

    def on_launch_ok(self, msg):
        self.status_lbl.setText(msg)
        self.launch_btn.setEnabled(True)
        self.launch_btn.setText("Open BDI Portal")

    def on_launch_fail(self, err):
        self.status_lbl.setText("Launch failed.")
        self.launch_btn.setEnabled(True)
        self.launch_btn.setText("Open BDI Portal")
        QMessageBox.critical(self, "Launch Error", err)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PortalLauncher()
    win.show()
    sys.exit(app.exec())