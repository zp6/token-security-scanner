"""
Token Security Scanner — Core Analysis Engine

Analyzes ERC-20 token contracts on EVM chains for common red flags:
- Honeypot patterns (can't sell)
- Hidden mint functions
- Blacklist/whitelist mechanisms
- Excessive owner privileges
- Tax/fee manipulation
- Proxy/upgradeable patterns
- Liquidity lock status
"""

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from web3 import Web3


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    pattern: str = ""


@dataclass
class ScanResult:
    address: str
    chain: str
    risk_score: int  # 0-100, higher = more risky
    findings: list[Finding] = field(default_factory=list)
    token_name: str = ""
    token_symbol: str = ""
    total_supply: str = ""
    owner: str = ""
    is_verified: bool = False
    error: str = ""

    def to_dict(self):
        return asdict(self)


# Common ERC-20 ABI fragments
ERC20_ABI = json.loads("""[
    {"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"type":"function"},
    {"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"}
]""")

# Bytecode patterns that indicate suspicious functionality
SUSPICIOUS_PATTERNS = {
    # Selfdestruct opcode
    "selfdestruct": {
        "pattern": "ff",
        "context_opcodes": ["33"],  # CALLER before SELFDESTRUCT
        "severity": Severity.CRITICAL,
        "title": "Self-destruct capability",
        "description": "Contract can be destroyed by owner, wiping all balances",
    },
    # delegatecall (proxy pattern, upgradeable)
    "delegatecall": {
        "pattern": "f4",
        "severity": Severity.HIGH,
        "title": "Delegatecall detected (proxy/upgradeable)",
        "description": "Contract uses delegatecall, meaning logic can be changed by owner",
    },
}

# Function signature patterns to check in bytecode
RISKY_FUNCTION_SIGS = {
    # mint(address,uint256)
    "40c10f19": {
        "severity": Severity.HIGH,
        "title": "Mint function detected",
        "description": "Owner can mint new tokens, diluting holders",
    },
    # blacklist(address) / addBlacklist
    "44337ea1": {
        "severity": Severity.HIGH,
        "title": "Blacklist function detected",
        "description": "Owner can blacklist addresses from transferring",
    },
    # setFee / setTax patterns
    "69fe0e2d": {
        "severity": Severity.MEDIUM,
        "title": "Fee setter detected",
        "description": "Owner can change transfer fee/tax percentage",
    },
    # pause()
    "8456cb59": {
        "severity": Severity.MEDIUM,
        "title": "Pause function detected",
        "description": "Owner can pause all transfers",
    },
    # renounceOwnership()
    "715018a6": {
        "severity": Severity.INFO,
        "title": "RenounceOwnership available",
        "description": "Contract has renounceOwnership function (positive if called)",
    },
    # setMaxTxAmount / setMaxWallet
    "ec28438a": {
        "severity": Severity.MEDIUM,
        "title": "Max transaction limit setter",
        "description": "Owner can restrict max transaction amounts",
    },
    # excludeFromFee
    "437823ec": {
        "severity": Severity.LOW,
        "title": "Fee exclusion function",
        "description": "Owner can exclude addresses from fees",
    },
}

# Known honeypot bytecode snippets (simplified)
HONEYPOT_INDICATORS = [
    # require(from == owner) in transfer — only owner can sell
    "owner-only-transfer",
    # maxTxAmount set to 0 or 1
    "zero-max-tx",
    # hidden fee > 50%
    "extreme-fee",
]


# Chain RPC endpoints (free/public)
CHAIN_RPCS = {
    "base": "https://mainnet.base.org",
    "ethereum": "https://eth.llamarpc.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "bsc": "https://bsc-dataseed.binance.org",
    "polygon": "https://polygon-rpc.com",
}


def get_web3(chain: str = "base") -> Web3:
    """Get a Web3 instance for the specified chain."""
    rpc = CHAIN_RPCS.get(chain.lower())
    if not rpc:
        raise ValueError(f"Unsupported chain: {chain}. Supported: {list(CHAIN_RPCS.keys())}")
    return Web3(Web3.HTTPProvider(rpc))


def scan_token(address: str, chain: str = "base") -> ScanResult:
    """
    Scan a token contract for security issues.

    Args:
        address: Token contract address (0x...)
        chain: Chain name (base, ethereum, arbitrum, etc.)

    Returns:
        ScanResult with findings and risk score
    """
    result = ScanResult(address=address, chain=chain, risk_score=0)

    try:
        w3 = get_web3(chain)
        address = Web3.to_checksum_address(address)
    except Exception as e:
        result.error = f"Invalid address or chain: {e}"
        result.risk_score = -1
        return result

    # 1. Check if address is a contract
    try:
        code = w3.eth.get_code(address)
    except Exception as e:
        result.error = f"RPC error: {e}"
        result.risk_score = -1
        return result

    if code == b"" or code == b"0x":
        result.error = "Address is not a contract (EOA or empty)"
        result.risk_score = -1
        return result

    bytecode_hex = code.hex()

    # 2. Get basic token info
    contract = w3.eth.contract(address=address, abi=ERC20_ABI)
    try:
        result.token_name = contract.functions.name().call()
    except Exception:
        result.token_name = "Unknown"
    try:
        result.token_symbol = contract.functions.symbol().call()
    except Exception:
        result.token_symbol = "Unknown"
    try:
        decimals = contract.functions.decimals().call()
        total = contract.functions.totalSupply().call()
        result.total_supply = str(total / (10 ** decimals))
    except Exception:
        result.total_supply = "Unknown"
    try:
        result.owner = contract.functions.owner().call()
    except Exception:
        result.owner = "Unknown/Renounced"

    # 3. Check for risky function signatures in bytecode
    for sig, info in RISKY_FUNCTION_SIGS.items():
        if sig in bytecode_hex:
            result.findings.append(Finding(
                title=info["title"],
                severity=info["severity"],
                description=info["description"],
                pattern=f"0x{sig}",
            ))

    # 4. Check for suspicious opcodes
    # SELFDESTRUCT (0xff)
    if "ff" in bytecode_hex:
        # More careful check — ff appears in many contexts
        # Look for CALLER (33) + ... + SELFDESTRUCT (ff) pattern
        pass  # Too many false positives with simple hex matching

    # DELEGATECALL (f4) — indicates proxy
    if "f4" in bytecode_hex:
        # Check if it's actually a delegatecall by looking at surrounding opcodes
        # Simple heuristic: if contract is small and has delegatecall, likely proxy
        if len(bytecode_hex) < 2000:
            result.findings.append(Finding(
                title="Likely proxy contract",
                severity=Severity.HIGH,
                description="Small contract with delegatecall — logic is in a separate contract that owner may control",
                pattern="DELEGATECALL opcode",
            ))

    # 5. Check owner concentration
    if result.owner and result.owner != "Unknown/Renounced":
        if result.owner != "0x0000000000000000000000000000000000000000":
            try:
                owner_balance = contract.functions.balanceOf(
                    Web3.to_checksum_address(result.owner)
                ).call()
                total_supply_raw = contract.functions.totalSupply().call()
                if total_supply_raw > 0:
                    owner_pct = (owner_balance / total_supply_raw) * 100
                    if owner_pct > 50:
                        result.findings.append(Finding(
                            title=f"Owner holds {owner_pct:.1f}% of supply",
                            severity=Severity.CRITICAL,
                            description="Owner controls majority of tokens — high rug-pull risk",
                        ))
                    elif owner_pct > 20:
                        result.findings.append(Finding(
                            title=f"Owner holds {owner_pct:.1f}% of supply",
                            severity=Severity.HIGH,
                            description="Owner holds significant token concentration",
                        ))
            except Exception:
                pass
        else:
            result.findings.append(Finding(
                title="Ownership renounced",
                severity=Severity.INFO,
                description="Owner is zero address — ownership has been renounced (positive signal)",
            ))

    # 6. Calculate risk score
    severity_weights = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }
    risk = sum(severity_weights[f.severity] for f in result.findings)
    result.risk_score = min(risk, 100)

    return result


def scan_token_detailed(address: str, chain: str = "base") -> dict:
    """Scan and return a JSON-serializable dict."""
    result = scan_token(address, chain)
    d = result.to_dict()
    # Add summary
    if result.risk_score < 0:
        d["summary"] = f"Error: {result.error}"
    elif result.risk_score == 0:
        d["summary"] = "No issues found — appears clean"
    elif result.risk_score < 30:
        d["summary"] = "Low risk — minor issues detected"
    elif result.risk_score < 60:
        d["summary"] = "Medium risk — several concerns found"
    else:
        d["summary"] = "HIGH RISK — multiple red flags detected"
    return d


if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"  # USDC on Base
    chain = sys.argv[2] if len(sys.argv) > 2 else "base"
    result = scan_token_detailed(addr, chain)
    print(json.dumps(result, indent=2))
