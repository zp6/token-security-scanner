# Token Security Scanner API

Scan ERC-20 tokens for honeypots, rug-pulls, and red flags across 6 EVM chains.

## Features

- **Multi-chain**: Base, Ethereum, Arbitrum, BSC, Polygon, Optimism
- **Bytecode analysis**: Detects mint functions, blacklists, pause mechanisms, fee setters, proxy patterns
- **Owner analysis**: Checks token concentration and ownership status
- **Risk scoring**: 0-100 score with detailed findings
- **Freemium**: 5 free scans/day, then 0.10 USDC/scan on Base

## Quick Start

```bash
pip install -r requirements.txt
python server.py
```

API runs at `http://localhost:8000`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info + pricing |
| GET | `/scan/{address}?chain=base` | Quick scan (free tier) |
| POST | `/scan` | Full scan (free or paid) |

## Example

```bash
# Scan USDC on Base
curl http://localhost:8000/scan/0x833589fcd6edb6e08f4c7c32d4f71b54bda02913?chain=base
```

## Docker

```bash
docker build -t token-scanner .
docker run -p 8000:8000 token-scanner
```

## Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

Uses the included `render.yaml` for one-click deployment.

## Pricing

- **Free tier**: 5 scans/day per IP
- **Paid tier**: 0.10 USDC per scan on Base mainnet
- Payment address: `0x8C0083EE1a611c917E3652a14f9Ab5c3a23948D3`

## License

MIT
