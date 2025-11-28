from fastapi import FastAPI
from auth import router as auth_router
from trigger import router as trigger_router
from webhook import router as webhook_router

app = FastAPI()

app.include_router(auth_router)
app.include_router(trigger_router)
app.include_router(webhook_router)

@app.get("/health")
def check():
    return {
        "fit_check": "check"
    }