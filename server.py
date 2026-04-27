"""
Token Scanner API Server

Endpoints:
  GET  /              — health check + info
  POST /scan          — scan a token (requires payment or free tier)
  GET  /scan/{address}?chain=base  — quick scan (GET variant)
  GET  /balance       — check service wallet balance

Pricing:
  Free tier: 5 scans/day per IP
  Paid: 0.10 USDC per scan (sent to service wallet on Base before request)
"""

import os
import time
import json
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from scanner import scan_token_detailed, CHAIN_RPCS

app = FastAPI(
    title="Token Security Scanner",
    description="Scan ERC-20 tokens for honeypots, rug-pulls, and red flags",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Config ---
WALLET_ADDRESS = os.environ.get(
    "SCANNER_WALLET",
    "0x8C0083EE1a611c917E3652a14f9Ab5c3a23948D3"
)
SCAN_PRICE_USDC = 0.10
FREE_SCANS_PER_DAY = 5

# --- Rate limiting (in-memory, resets on restart) ---
rate_limits: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(ip: str) -> bool:
    """Check if IP has free scans remaining today."""
    now = time.time()
    day_start = now - 86400
    # Clean old entries
    rate_limits[ip] = [t for t in rate_limits[ip] if t > day_start]
    return len(rate_limits[ip]) < FREE_SCANS_PER_DAY


def record_scan(ip: str):
    rate_limits[ip].append(time.time())


# --- Models ---
class ScanRequest(BaseModel):
    address: str = Field(..., description="Token contract address (0x...)")
    chain: str = Field("base", description="Chain name: base, ethereum, arbitrum, bsc, polygon, optimism")
    tx_hash: str | None = Field(None, description="USDC payment tx hash (optional, for paid tier)")


# --- Endpoints ---
@app.get("/")
async def root():
    return {
        "service": "Token Security Scanner",
        "version": "0.1.0",
        "pricing": {
            "free_tier": f"{FREE_SCANS_PER_DAY} scans/day per IP",
            "paid": f"{SCAN_PRICE_USDC} USDC per scan on Base",
            "payment_address": WALLET_ADDRESS,
        },
        "supported_chains": list(CHAIN_RPCS.keys()),
        "endpoints": {
            "POST /scan": "Scan a token",
            "GET /scan/{address}": "Quick scan (free tier)",
        },
    }


@app.get("/scan/{address}")
async def quick_scan(address: str, chain: str = "base", request: Request = None):
    """Free-tier quick scan with rate limiting."""
    client_ip = request.client.host if request else "unknown"

    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=402,
            detail={
                "error": "Free tier limit reached",
                "message": f"Send {SCAN_PRICE_USDC} USDC to {WALLET_ADDRESS} on Base and include tx_hash in POST /scan",
                "payment_address": WALLET_ADDRESS,
                "price_usdc": SCAN_PRICE_USDC,
            },
        )

    record_scan(client_ip)
    result = scan_token_detailed(address, chain)
    result["tier"] = "free"
    result["scans_remaining"] = FREE_SCANS_PER_DAY - len(rate_limits[client_ip])
    return result


@app.post("/scan")
async def paid_scan(body: ScanRequest, request: Request = None):
    """Scan a token. Free tier or paid with tx_hash."""
    client_ip = request.client.host if request else "unknown"

    if body.tx_hash:
        # TODO: Verify the tx_hash is a valid USDC transfer to our wallet
        # For now, accept any tx_hash (will implement verification)
        result = scan_token_detailed(body.address, body.chain)
        result["tier"] = "paid"
        result["tx_verified"] = False  # Will be True once verification is implemented
        return result

    # Fall back to free tier
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=402,
            detail={
                "error": "Free tier limit reached",
                "message": f"Send {SCAN_PRICE_USDC} USDC to {WALLET_ADDRESS} on Base",
                "payment_address": WALLET_ADDRESS,
                "price_usdc": SCAN_PRICE_USDC,
            },
        )

    record_scan(client_ip)
    result = scan_token_detailed(body.address, body.chain)
    result["tier"] = "free"
    result["scans_remaining"] = FREE_SCANS_PER_DAY - len(rate_limits[client_ip])
    return result


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
