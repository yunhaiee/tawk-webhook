# Fully working Tawk.to webhook receiver for MCP server (Python)
# Handles "new chat transcript" event securely with HMAC-SHA1 verification

from fastapi import FastAPI, Request, Header, HTTPException
import hmac
import hashlib
import json

app = FastAPI()

WEBHOOK_SECRET = "6b8e00c470a34f4d5d7b2fe0f73631a3217612eb2beed1675dfd82f624c306b3691344462b0ebbd7dbb2f2168455cf19"  # Replace with your Tawk.to webhook secret key

# Utility function to verify Tawk.to webhook signature
def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    calculated_signature = hmac.new(WEBHOOK_SECRET.encode(), raw_body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(calculated_signature, signature_header)

@app.post("/api/tawk-transcript-webhook")
async def tawk_transcript_webhook(request: Request, x_tawk_signature: str = Header(None)):
    try:
        raw_body = await request.body()
        if not x_tawk_signature:
            raise HTTPException(status_code=400, detail="Missing X-Tawk-Signature header")

        if not verify_signature(raw_body, x_tawk_signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

        payload = json.loads(raw_body.decode())

        # Process only "chat:transcript_created" events safely
        if payload.get("event") == "chat:transcript_created":
            chat_data = payload.get("chat", {})
            visitor = chat_data.get("visitor", {})
            messages = chat_data.get("messages", [])

            # Example: Log chat ID and visitor email
            print(f"Received transcript for chat ID: {chat_data.get('id')}")
            print(f"Visitor email: {visitor.get('email')}")

            # Example: Log each message
            for msg in messages:
                sender_type = msg.get("sender", {}).get("t")
                sender_name = msg.get("sender", {}).get("n", "unknown")
                text = msg.get("msg")
                print(f"[{sender_type}] {sender_name}: {text}")

            # TODO: Insert into your MCP system, forward to Discord, store in DB, etc.

        return {"status": "ok"}

    except Exception as e:
        print(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing error")

# To run:
# uvicorn tawk_webhook_receiver:app --host 0.0.0.0 --port 8000
# Deploy this on Render/Fly.io/Railway or your VPS to get a public HTTPS endpoint for Tawk.to webhook.
