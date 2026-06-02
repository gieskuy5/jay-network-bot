# JAY Network Bot

Multi-account automation for JAY Network campaign + mining with proxy support.

## Files

| File | Description |
|------|-------------|
| `daily.py` | Campaign tasks — checkin, complete tasks, daily claim |
| `mining.py` | Mining — multi-wallet from mnemonic, unique fingerprint per wallet |
| `auth.txt` | JWT session tokens (1 line = 1 token) |
| `mnemonic.txt` | BIP39 mnemonics (1 line = 1 mnemonic) |
| `proxy.txt` | Proxies (1 line = 1 proxy) |

## Setup

### auth.txt (Campaign tokens)

```
eyJhbGci...token1
eyJhbGci...token2
```

Get token: Login campaign → F12 → Application → Cookies → `__Secure-next-auth.session-token`

### mnemonic.txt (Mining wallets)

```
word1 word2 word3 ... word12
word1 word2 word3 ... word24
```

Auto-derives `yjay1...` wallet address from each mnemonic (BIP44 m/44'/118'/0'/0/0).

### proxy.txt (Optional)

```
http://host:port
http://user:pass@host:port
socks5://host:port
socks4://host:port
host:port
```

If file doesn't exist or is empty, uses local network directly.

## Usage

```bash
# Campaign
python3 daily.py checkin    # Daily checkin all accounts
python3 daily.py check      # Check session all accounts
python3 daily.py complete   # Complete all pending tasks
python3 daily.py status     # Detailed status

# Mining
python3 mining.py           # Mine all wallets concurrently
```

## Multi-Account Fingerprint

Each account/wallet gets a unique fingerprint:
- User-Agent (Chrome/Firefox/Safari × Windows/Mac/Linux)
- Screen resolution
- Timezone
- Device ID
- Fingerprint hash

Sent via headers: `X-Client-Fingerprint`, `X-Device-ID`, `User-Agent`

## Proxy Support

Each account rotates through proxies (round-robin).
Supports: HTTP, HTTPS, SOCKS4, SOCKS5, with/without auth.

| Component | Proxy Support |
|-----------|--------------|
| daily.py (requests) | ✅ via `proxies=` |
| mining.py HTTP (aiohttp) | ✅ via `proxy=` |
| mining.py WS (websockets) | ✅ via `proxy=` |

## Dependencies

```bash
pip3 install requests websockets aiohttp bip-utils
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/session` | Check login |
| GET | `/api/dashboard-data` | Tasks + progress |
| GET | `/api/daily-login` | Daily login status |
| POST | `/api/daily-login` | Claim daily (`{"day": N}`) |
| POST | `/api/task/complete` | Complete task |
| GET | `/api/referral` | Referral info |
| POST | `/api/referral` | Register referral |
| GET | `/api/leaderboard` | Leaderboard |
