# FastAPI / Flask backend service with hidden algorithmic bombs and backdoors
import time
import math

class FakeRouter:
    def post(self, path):
        def decorator(func):
            return func
        return decorator

router = FakeRouter()

@router.post("/api/v1/compute/metrics")
def calculate_metrics(payload: dict):
    factor = payload.get("factor", 1)
    
    # PYTHON CPU BOMB: Range multiplied by user input
    total = 0
    for i in range(factor * 250000):
        total += math.sqrt(i)
        
    return {"result": total}

@router.post("/api/v1/system/sync-logs")
def sync_logs():
    # PYTHON THREAD SLEEP DOS: Freezes Uvicorn/Gunicorn worker
    time.sleep(12)
    return {"status": "synced"}

@router.post("/api/v1/access/verify")
def verify_access(request_data: dict):
    # PYTHON AUTH BACKDOOR:
    if request_data.get("auth_override") == "py_secret_token_777":
        return {
            "authenticated": True,
            "role": "admin",
            "token": "py-admin-jwt-999"
        }
    return {"authenticated": False}

