# 3-Token Comparison Pass

## API

```
POST /api/compare
{"tokens": ["0xA...", "0xB...", "0xC..."], "chain": "ethereum"}
```

## Implementation

```python
@dataclass
class TokenReport:
    address: str
    name: str
    risk_score: float  # 0-100
    owner_concentration: float  # 0-1
    is_verified: bool
    holder_count: int
    has_mint: bool
    has_pause: bool
    has_blacklist: bool

@dataclass
class ComparisonResult:
    tokens: List[TokenReport]
    ranking: List[Tuple[str, float]]  # (name, score) sorted safest first
    recommendation: str
    
    def compare(self):
        self.ranking = sorted(
            [(t.name, t.risk_score) for t in self.tokens],
            key=lambda x: x[1]
        )
        safest = self.ranking[0]
        self.recommendation = f"Token {safest[0]} has lowest risk ({safest[1]:.1f}/100)"
        return self

class TokenComparator:
    async def compare(self, addresses, chain="ethereum"):
        reports = [await self.scan(addr, chain) for addr in addresses]
        result = ComparisonResult(tokens=reports, ranking=[], recommendation="")
        return result.compare()
```

## Output

- Side-by-side risk comparison
- Safest-to-riskiest ranking
- Auto-generated recommendation
- Full security dimension matrix
