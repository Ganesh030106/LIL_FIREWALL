#!/usr/bin/env python3
"""
AI-Powered Contextual Firewall for Traffic Anomaly Detection - All-in-One Startup Script
Automatically sets up and runs the entire project in one command.
Run: python run.py
"""

import os
import sys
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

# Load environment variables from backend/.env if it exists
def load_env_file(dotenv_path: Path) -> None:
    if dotenv_path.exists():
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'").strip('"')
                    if key and key not in os.environ:
                        os.environ[key] = val

load_env_file(Path(".env"))
load_env_file(Path("backend/.env"))

# Avoid re-executing the launcher from a project venv; it can cause
# confusing Ctrl+C tracebacks and unnecessary process nesting.
venv_python = Path(__file__).resolve().parent / "backend" / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
if venv_python.exists() and sys.executable.lower() != str(venv_python).lower():
    print(f"Detected project venv at {venv_python}; continuing with the active interpreter.")

# Fix Unicode output on Windows (cp1252 can't handle emoji)
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)


class Colors:
    """Terminal color codes."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_header(text: str) -> None:
    """Print colored header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.END}\n")


def print_success(text: str) -> None:
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_info(text: str) -> None:
    """Print info message."""
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")


def print_warning(text: str) -> None:
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_error(text: str) -> None:
    """Print error message."""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def run_command(cmd: list, description: str, check: bool = True, cwd: Optional[str] = None) -> Optional[str]:
    """Run a shell command and return output."""
    try:
        print_info(f"{description}...")
        # On Windows, use shell=True so that .cmd/.bat scripts (like npm) are found
        use_shell = sys.platform == "win32"
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            shell=use_shell,
            cwd=cwd,
        )
        if result.returncode == 0:
            print_success(description)
            return result.stdout.strip()
        else:
            if check:
                print_error(f"{description} failed: {result.stderr}")
                return None
            return result.stdout.strip()
    except FileNotFoundError:
        print_error(f"Command not found: {cmd[0]}")
        return None
    except Exception as e:
        print_error(f"{description} failed: {str(e)}")
        return None


def check_python_version() -> bool:
    """Check if Python version is 3.8+."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_error(f"Python 3.8+ required, got {version.major}.{version.minor}")
        return False
    print_success(f"Python {version.major}.{version.minor}.{version.micro} detected")
    return True


def check_node_installed() -> bool:
    """Check if Node.js and npm are installed."""
    result = run_command(["node", "--version"], "Checking Node.js", check=False)
    if not result:
        print_error("Node.js not installed. Visit https://nodejs.org/")
        return False
    print_success(f"Node.js {result} detected")
    return True


def check_git_installed() -> bool:
    """Check if git is installed (optional)."""
    result = run_command(["git", "--version"], "Checking Git", check=False)
    if result:
        print_success(f"{result}")
        return True
    return False


def install_python_dependencies() -> bool:
    """Install Python dependencies from requirements.txt."""
    try:
        import fastapi, uvicorn, scapy, psycopg2, sklearn, joblib, watchdog
        print_success("Python dependencies already satisfied")
        return True
    except ImportError:
        pass

    req_path = Path("backend/requirements.txt")
    if not req_path.exists():
        print_error(f"{req_path} not found")
        return False

    result = run_command(
        [sys.executable, "-m", "pip", "install", "-r", str(req_path)],
        "Installing Python dependencies",
        check=False,
    )
    return result is not None


def install_npm_dependencies() -> bool:
    """Install npm dependencies."""
    package_path = Path("frontend/package.json")
    if not package_path.exists():
        print_warning(f"{package_path} not found, skipping npm install")
        return True

    if (Path("frontend/node_modules").exists() and
        Path("frontend/node_modules/react").exists()):
        print_success("npm dependencies already installed")
        return True

    result = run_command(
        ["npm", "install"],
        "Installing npm dependencies",
        check=False,
        cwd="frontend",
    )
    return result is not None


def generate_phishing_model() -> bool:
    """Generate the phishing detection model."""
    model_file = Path("backend/phishing_model.joblib")
    if model_file.exists():
        print_success(f"Phishing model already exists: {model_file}")
        return True

    print_info("Generating phishing detection model...")
    try:
        sys.path.insert(0, str(Path("backend").resolve()))
        import importlib
        model_generator = importlib.import_module("model_generator")
        train_model = model_generator.train_model

        model_path = train_model(model_file)
        print_success(f"Phishing model generated: {model_path}")
        return True
    except ImportError as e:
        print_warning(f"Could not import model_generator, model will be auto-generated on first run: {e}")
        return True
    except Exception as e:
        print_error(f"Failed to generate model: {str(e)}")
        return False


def create_directories() -> bool:
    """Create necessary directories."""
    directories = ["backend/sandbox", "backend/data", "backend/logs"]
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print_success(f"Created/verified directory: {directory}/")
    return True


def initialize_database() -> bool:
    """Initialize SQLite database."""
    print_info("Initializing database...")
    try:
        sys.path.insert(0, str(Path("backend").resolve()))
        import importlib
        database = importlib.import_module("storage.database")
        db_path = os.getenv("VOLCANO_DB_PATH", "backend/volcano.db")
        db = database.Database(db_path)
        print_success(f"Database initialized: {db_path}")
        return True
    except Exception as e:
        print_error(f"Failed to initialize database: {str(e)}")
        return False


def start_backend() -> Optional[subprocess.Popen]:
    """Start the FastAPI backend server."""
    port = os.getenv("PORT", "8000")
    print_header("Starting Backend (FastAPI)")
    print_info(f"Backend starting on http://127.0.0.1:{port}")
    print_info(f"Swagger docs: http://127.0.0.1:{port}/docs")

    try:
        process = subprocess.Popen(
            [sys.executable, "-u", "app.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd="backend",
        )
        print_success("Backend process started (PID: {})".format(process.pid))
        return process
    except Exception as e:
        print_error(f"Failed to start backend: {str(e)}")
        return None


def start_frontend() -> Optional[subprocess.Popen]:
    """Start the Vite frontend dev server."""
    print_header("Starting Frontend (Vite + React)")
    print_info("Frontend starting on http://localhost:5173")

    try:
        # On Windows, use shell=True so that npm.cmd is found
        use_shell = sys.platform == "win32"
        process = subprocess.Popen(
            ["npm", "run", "dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=use_shell,
            cwd="frontend",
        )
        print_success("Frontend process started (PID: {})".format(process.pid))
        return process
    except Exception as e:
        print_error(f"Failed to start frontend: {str(e)}")
        return None


def read_process_output(process: Optional[subprocess.Popen], process_name: str) -> None:
    """Read and print process output in real-time."""
    if not process or not process.stdout:
        return

    try:
        for line in iter(process.stdout.readline, ""):
            if line:
                print(f"{Colors.BOLD}[{process_name}]{Colors.END} {line.rstrip()}")
    except:
        pass


def print_startup_info() -> None:
    """Print startup information and URLs."""
    print_header("🛡️ AI-Powered Contextual Firewall for Traffic Anomaly Detection - Running")

    info = f"""
{Colors.BOLD}Services Running:{Colors.END}
  • {Colors.CYAN}Backend API{Colors.END}:      http://127.0.0.1:8000
  • {Colors.CYAN}API Docs (Swagger){Colors.END}: http://127.0.0.1:8000/docs
  • {Colors.CYAN}Dashboard{Colors.END}:       http://localhost:5173
  • {Colors.CYAN}Health Check{Colors.END}:    http://127.0.0.1:8000/api/health

{Colors.BOLD}Available APIs:{Colors.END}
  • GET  /api/alerts              - Live security alerts
  • GET  /api/metrics             - Traffic metrics
  • GET  /api/threat-summary      - AI threat score
  • GET  /api/firewall-insights   - Port & protocol analysis
  • GET  /api/rules               - Firewall rules
  • GET  /api/risk/devices        - High-risk devices
  • GET  /api/risk/stats          - Risk statistics
  • POST /api/check-url           - Phishing detection
  • POST /api/copilot/ask         - Natural language queries
  • POST /api/rules               - Create firewall rule
  • POST /api/killswitch          - Emergency network isolation

{Colors.BOLD}Quick Test Commands:{Colors.END}
  curl http://127.0.0.1:8000/api/health
  curl http://127.0.0.1:8000/api/alerts
  curl http://127.0.0.1:8000/api/metrics

{Colors.BOLD}Environment:{Colors.END}
  • Database:    ./volcano.db
  • Sandbox:     ./sandbox/
  • Models:      ./phishing_model.joblib

{Colors.YELLOW}⚠️  Press Ctrl+C to stop both services{Colors.END}
"""
    print(info)


def main() -> None:
    """Main setup and run function."""
    import argparse
    parser = argparse.ArgumentParser(description="AI-Powered Contextual Firewall for Traffic Anomaly Detection All-in-One Startup Script")
    parser.add_argument("--production", "-p", action="store_true", help="Run in production mode (compiles frontend, serves via backend)")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the backend on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind the backend to")
    args = parser.parse_args()

    # Apply configuration to environment
    os.environ["PORT"] = str(args.port)

    # In production, we also configure allowed origins if not already configured
    if args.production and "VOLCANO_ALLOWED_ORIGINS" not in os.environ:
        os.environ["VOLCANO_ALLOWED_ORIGINS"] = "*"

    print_header("🛡️ AI-Powered Contextual Firewall for Traffic Anomaly Detection Setup")
    print("Checking prerequisites...")
    print()

    if not check_python_version():
        sys.exit(1)

    if not check_node_installed():
        sys.exit(1)

    check_git_installed()
    print()

    print_header("Installation Phase")

    if not install_python_dependencies():
        print_warning("Failed to install Python dependencies, continuing...")

    if not install_npm_dependencies():
        print_warning("Failed to install npm dependencies, continuing...")

    if args.production:
        print_header("Compiling Frontend (Production Build)")
        # Run npm run build
        build_result = run_command(["npm", "run", "build"], "Building frontend static assets", check=False, cwd="frontend")
        if not build_result:
            print_warning("Failed to build frontend static assets. Continuing...")

    if not generate_phishing_model():
        print_warning("Failed to generate model, will auto-generate on first run")

    if not create_directories():
        print_error("Failed to create directories")
        sys.exit(1)

    if not initialize_database():
        print_warning("Failed to initialize database, will auto-initialize on first run")

    print()
    print_header("Starting Services")

    backend_process = start_backend()
    time.sleep(2)

    frontend_process = None
    if not args.production:
        frontend_process = start_frontend()
        time.sleep(3)

    if not backend_process or (not args.production and not frontend_process):
        print_error("Failed to start one or more services")
        sys.exit(1)

    # Print appropriate startup information
    if args.production:
        print_header("🛡️ AI-Powered Contextual Firewall for Traffic Anomaly Detection - Production Mode")
        info = f"""
{Colors.BOLD}Services Running:{Colors.END}
  • {Colors.CYAN}Production UI & API{Colors.END}: http://localhost:{args.port}
  • {Colors.CYAN}API Docs (Swagger){Colors.END}:  http://localhost:{args.port}/docs
  • {Colors.CYAN}Health Check{Colors.END}:       http://localhost:{args.port}/api/health

{Colors.BOLD}Environment:{Colors.END}
  • Database:    ./volcano.db (or external PostgreSQL via VOLCANO_DB_PATH)
  • Sandbox:     ./sandbox/
  • Models:      ./phishing_model.joblib

{Colors.YELLOW}⚠️  Press Ctrl+C to stop the services{Colors.END}
"""
        print(info)
    else:
        print_startup_info()

    try:
        backend_thread = threading.Thread(
            target=read_process_output,
            args=(backend_process, "BACKEND"),
            daemon=True,
        )
        backend_thread.start()

        if frontend_process:
            frontend_thread = threading.Thread(
                target=read_process_output,
                args=(frontend_process, "FRONTEND"),
                daemon=True,
            )
            frontend_thread.start()

        while True:
            if backend_process.poll() is not None:
                print_error("Backend process exited")
                backend_process = start_backend()

            if frontend_process and frontend_process.poll() is not None:
                print_error("Frontend process exited")
                frontend_process = start_frontend()

            time.sleep(1)

    except KeyboardInterrupt:
        print_header("Shutting Down")
        print_info("Stopping backend...")
        if backend_process:
            backend_process.terminate()
            backend_process.wait(timeout=5)
        print_success("Backend stopped")

        if frontend_process:
            print_info("Stopping frontend...")
            frontend_process.terminate()
            frontend_process.wait(timeout=5)
            print_success("Frontend stopped")

        print_success("All services stopped")
        print_info("To run again: python run.py")
        sys.exit(0)
    except Exception as e:
        print_error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
