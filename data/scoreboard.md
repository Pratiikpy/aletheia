# Verity Accuracy Scoreboard

Generated 2026-07-08T03:34:41.795Z · tier=flag · n=17

| Metric | Verity | GoPlus baseline |
|---|---|---|
| Accuracy | 88.2% | 87.5% |
| Specificity (clean kept clean) | 100.0% | 100.0% |
| False-positive rate | 0.0% | 0.0% |
| Precision | 100.0% | — |
| Recall | 33.3% | 0.0% |

> Positive-class honeypot RECALL is additionally validated by a deterministic on-fork honeypot fixture (scripts/test-honeypot-positive.mts). Real honeypot addresses expand this labeled set over time.

## Per-token

| Token | Chain | Label | Verity | Score | Correct |
|---|---|---|---|---|---|
| USDT | ethereum | clean | CAUTION | 95 | ✓ |
| USDC | ethereum | clean | GO | 92 | ✓ |
| WETH | ethereum | clean | GO | 100 | ✓ |
| PEPE | ethereum | clean | GO | 91 | ✓ |
| LINK | ethereum | clean | GO | 91 | ✓ |
| UNI | ethereum | clean | GO | 99 | ✓ |
| SHIB | ethereum | clean | GO | 89 | ✓ |
| LDO | ethereum | clean | GO | 90 | ✓ |
| ENS | ethereum | clean | CAUTION | 68 | ✓ |
| stETH | ethereum | clean | CAUTION | 70 | ✓ |
| CAKE | bsc | clean | CAUTION | 71 | ✓ |
| BSC-USD | bsc | clean | CAUTION | 70 | ✓ |
| WBNB | bsc | clean | CAUTION | 71 | ✓ |
| USDC.base | base | clean | CAUTION | 71 | ✓ |
| HONEYPOT | ethereum | honeypot | CAUTION | 48 | ✗ |
| Etherscan-hp | ethereum | honeypot | CAUTION | 48 | ✗ |
| HONEYPOT-FIXTURE | ethereum | honeypot | AVOID | 5 | ✓ |
