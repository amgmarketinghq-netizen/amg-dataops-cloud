import sys
import os

# Dynamic Root Path Resolution for Vercel Serverless Runtime
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from backend.main import app
except Exception as e:
    from fastapi import FastAPI
    app = FastAPI()
    
    @app.get("/{full_path:path}")
    def catch_all(full_path: str):
        return {
            "status": "IMPORT_ERROR",
            "message": "Backend module import failed in Serverless environment",
            "error_detail": str(e)
        }
