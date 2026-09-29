import os
import sys
import time
import webbrowser
import threading
from dotenv import load_dotenv

# Fix Windows console encoding for emojis
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Ensure backend path is in sys.path
root_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
backend_dir = os.path.join(root_dir, 'backend')

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Load .env file if available
env_path = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.abspath(os.path.dirname(__file__)), '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()

def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    import uvicorn
    from backend.main import app

    print("==================================================")
    print("      🚀 Shipcheck AI Pre-Ship Auditor           ")
    print("==================================================")
    print("Starting server at http://127.0.0.1:8001...")

    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info", lifespan="off")
