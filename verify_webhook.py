import os
import base64
import hmac
import hashlib
from fastapi import Request, HTTPException
from dotenv import load_dotenv
load_dotenv()

def verify_webhook_signature(request: Request, body: bytes) -> bool:
    """Verify Composio webhook signature as middleware for FastAPI endpoints."""
    print("--- verify_webhook_signature called ---")
    webhook_signature = request.headers.get("webhook-signature")
    webhook_id = request.headers.get("webhook-id")
    webhook_timestamp = request.headers.get("webhook-timestamp")
    webhook_secret = os.getenv("COMPOSIO_WEBHOOK_SECRET")
    print(f"webhook_signature: {webhook_signature}")
    print(f"webhook_id: {webhook_id}")
    print(f"webhook_timestamp: {webhook_timestamp}")
    print(f"webhook_secret: {webhook_secret}")
    print(f"body: {body}")

    if not all([webhook_signature, webhook_id, webhook_timestamp, webhook_secret]):
        print("Missing required webhook headers or secret")
        return False

    if not webhook_signature.startswith("v1,"):
        print("Invalid signature format")
        return False

    received = webhook_signature[3:]
    signing_string = f"{webhook_id}.{webhook_timestamp}.{body.decode()}"
    print(f"signing_string: {signing_string}")
    expected = base64.b64encode(
        hmac.new(webhook_secret.encode(), signing_string.encode(), hashlib.sha256).digest()
    ).decode()
    print(f"expected signature: {expected}")
    print(f"received signature: {received}")

    if not hmac.compare_digest(received, expected):
        print("Invalid webhook signature")
        return False

    print("Verification result: True")
    return True