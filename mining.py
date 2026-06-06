#!/usr/bin/env python3
"""
JAY Network Mining — Multi-Wallet from mnemonic.txt
1 line = 1 BIP39 mnemonic → derive yjay wallet → mine
Each wallet gets unique fingerprint
Proxy: proxy.txt (1 line = 1 proxy, supports http/socks4/socks5)
"""

import asyncio
import base64
import hashlib
import ssl
import json
import os
import random
import sys
import time
import uuid

try:
    import websockets
except ImportError:
    os.system("pip3 install websockets -q")
    import websockets

try:
    import aiohttp
except ImportError:
    os.system("pip3 install aiohttp -q")
    import aiohttp

try:
    from bip_utils import Bip44, Bip44Coins, Bip39SeedGenerator, Bip44Changes, Bech32Encoder
except ImportError:
    os.system("pip3 install bip-utils -q")
    from bip_utils import Bip44, Bip44Coins, Bip39SeedGenerator, Bip44Changes, Bech32Encoder


POOL_API = "https://api-pool.winnode.xyz"
POOL_WS = "wss://api-pool.winnode.xyz"
TOKEN_API = "https://mining.thejaynetwork.com/api/ws-token"
BALANCE_API = "https://api-jayn.winnode.xyz/cosmos/bank/v1beta1/balances"
HISTORY_API = f"{POOL_API}/api/history"
DIR = os.path.dirname(os.path.abspath(__file__))
MNEMONIC_FILE = os.path.join(DIR, "mnemonic.txt")
PROXY_FILE = os.path.join(DIR, "proxy.txt")

THREADS = 16
SHARE_MIN_INTERVAL = 1.0
SHARE_MAX_INTERVAL = 2.5
HEARTBEAT_INTERVAL = 15
SHARES_BEFORE_REFRESH = 50
HASHRATE_PER_THREAD = 15
SHARE_CHANCE = 0.7


# ─── Proxy Loader ──────────────────────────────────────────────

def load_proxies():
    """Load proxies from proxy.txt. Supports:
    http://host:port, socks5://host:port, socks4://host:port
    http://user:pass@host:port, host:port (treated as http)
    """
    if not os.path.exists(PROXY_FILE):
        return []
    with open(PROXY_FILE) as f:
        lines = [l.strip() for l in f if l.strip()]
    proxies = []
    for line in lines:
        if "://" in line:
            proxies.append(line)
        elif "@" in line:
            proxies.append(f"http://{line}")
        else:
            proxies.append(f"http://{line}")
    return proxies


PROXIES = load_proxies()
if PROXIES:
    print(f"Loaded {len(PROXIES)} proxy(ies)")


def get_proxy(index):
    """Get proxy URL for aiohttp/websockets. Returns None if no proxies."""
    if not PROXIES:
        return None
    return PROXIES[index % len(PROXIES)]


# ─── Wallet Derivation ─────────────────────────────────────────

def mnemonic_to_jay_wallet(mnemonic: str) -> str:
    seed = Bip39SeedGenerator(mnemonic.strip()).Generate()
    bip44 = Bip44.FromSeed(seed, Bip44Coins.COSMOS)
    acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    pub_key_bytes = acc.PublicKey().RawCompressed().ToBytes()
    sha = hashlib.sha256(pub_key_bytes).digest()
    ripemd = hashlib.new('ripemd160', sha).digest()
    return Bech32Encoder.Encode('yjay', ripemd)


# ─── Fingerprint ───────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

SCREENS = ["1920x1080", "2560x1440", "1366x768", "1536x864", "1440x900",
           "1680x1050", "1280x720", "2560x1600", "3840x2160", "1920x1200"]

TIMEZONES = ["Asia/Jakarta", "Asia/Makassar", "Asia/Jayapura", "America/New_York",
             "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Asia/Tokyo",
             "Asia/Singapore", "Australia/Sydney"]


def gen_fingerprint(index):
    ua = USER_AGENTS[index % len(USER_AGENTS)]
    screen = SCREENS[index % len(SCREENS)]
    tz = TIMEZONES[index % len(TIMEZONES)]
    device_id = f"device_{int(time.time()*1000)}_{os.urandom(8).hex()[:13]}"
    fp_hash = hashlib.sha256(f"{ua}{screen}{tz}{device_id}".encode()).hexdigest()[:32]
    return {"ua": ua, "screen": screen, "tz": tz, "device_id": device_id, "fingerprint": fp_hash}


def gen_session_id():
    return f"session_{int(time.time()*1000)}_{uuid.uuid4().hex[:10]}"


def gen_request_id():
    return uuid.uuid4().hex[:16]


def make_captcha_token(wallet):
    answer = random.randint(2, 40)
    raw = f"{int(time.time()*1000)}:{wallet[-8:]}:{answer}"
    return base64.b64encode(raw.encode()).decode()


def compute_share_hash(wallet, nonce, timestamp, job_id):
    r = f"{wallet}{nonce}{timestamp}{job_id}"
    return "".join(format((ord(r[t % len(r)]) + t) % 16, 'x') for t in range(64))


def format_hashrate(h):
    if h >= 1e12: return f"{h/1e12:.1f} TH/s"
    elif h >= 1e9: return f"{h/1e9:.1f} GH/s"
    elif h >= 1e6: return f"{h/1e6:.1f} MH/s"
    elif h >= 1e3: return f"{h/1e3:.1f} KH/s"
    return f"{h:.0f} H/s"


def ws_is_open(ws):
    try:
        return ws.state == websockets.State.OPEN
    except:
        return False


# ─── Miner Stats ───────────────────────────────────────────────

class MinerStats:
    def __init__(self, name, wallet, fp, proxy):
        self.name = name
        self.wallet = wallet
        self.fp = fp
        self.proxy = proxy
        self.shares_submitted = 0
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.blocks_found = 0
        self.rewards_earned = 0.0
        self.start_time = None
        self.connected = False
        self.mining = False
        self.current_difficulty = 1_000_000
        self.current_job_id = ""
        self.step = 0
        self.hashrate = 0.0
        self.balance = 0.0
        self.miner_id = ""
        self.token_gen = 0


# ─── Helpers ───────────────────────────────────────────────────

async def fetch_ws_token(wallet, session_id, device_id, token_gen, fp, proxy_url=None):
    headers = {
        "Content-Type": "application/json",
        "Origin": "https://mining.thejaynetwork.com",
        "Referer": "https://mining.thejaynetwork.com/",
        "User-Agent": fp["ua"],
        "X-Client-Fingerprint": fp["fingerprint"],
        "X-Token-Generation": str(token_gen + 1),
        "X-Request-ID": gen_request_id(),
        "X-Session-ID": session_id,
        "X-Device-ID": device_id,
        "X-Client-UA": base64.b64encode(fp["ua"].encode()).decode()[:32],
        "X-Client-Screen": base64.b64encode(fp["screen"].encode()).decode()[:16],
        "X-Client-TZ": base64.b64encode(fp["tz"].encode()).decode()[:16],
    }
    ssl_ctx = ssl.create_default_context()
    conn = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.post(TOKEN_API, json={"wallet": wallet}, headers=headers,
                                proxy=proxy_url,
                                timeout=aiohttp.ClientTimeout(total=15, connect=5)) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"Token HTTP {resp.status}: {text[:200]}")
            data = await resp.json()
            if "token" not in data:
                raise Exception(f"No token: {data}")
            return data


async def check_balance(wallet, proxy_url=None):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{BALANCE_API}/{wallet}",
                                   proxy=proxy_url,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200: return 0.0
                data = await resp.json()
                for bal in data.get("balances", []):
                    if bal.get("denom") == "ujay":
                        return int(bal["amount"]) / 1_000_000
    except:
        pass
    return 0.0


async def check_history(wallet, proxy_url=None):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{HISTORY_API}/{wallet}",
                                   proxy=proxy_url,
                                   timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200: return []
                return (await resp.json()).get("history", [])
    except:
        return []


async def heartbeat_loop(ws, session_id, device_id):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if ws_is_open(ws):
                await ws.send(json.dumps({
                    "type": "ping",
                    "payload": {"sessionId": session_id, "deviceId": device_id, "timestamp": int(time.time() * 1000)}
                }))
    except asyncio.CancelledError:
        pass
    except:
        pass


async def submit_shares(ws, stats, session_id, device_id):
    wallet = stats.wallet
    job_id = stats.current_job_id or f"job-{int(time.time())}"
    difficulty = stats.current_difficulty

    for _ in range(random.randint(8, 20)):
        if not ws_is_open(ws) or not stats.mining:
            break
        await asyncio.sleep(random.uniform(SHARE_MIN_INTERVAL, SHARE_MAX_INTERVAL))
        if random.random() > SHARE_CHANCE:
            continue

        nonce = random.randint(0, 2**32)
        timestamp = int(time.time() * 1000)
        hash_val = compute_share_hash(wallet, nonce, timestamp, job_id)
        stats.hashrate = THREADS * HASHRATE_PER_THREAD * random.uniform(0.8, 1.2) * 1000
        stats.shares_submitted += 1

        try:
            await ws.send(json.dumps({
                "type": "submit_share",
                "payload": {
                    "nonce": nonce, "hash": hash_val, "timestamp": timestamp,
                    "jobId": job_id, "difficulty": difficulty,
                    "sessionId": session_id, "deviceId": device_id,
                    "minerId": stats.miner_id or None,
                }
            }))
            print(f"  [{stats.name}] Share #{stats.shares_submitted} (hr={format_hashrate(stats.hashrate)})")
        except:
            break


async def mining_loop(stats):
    wallet = stats.wallet
    fp = stats.fp
    device_id = fp["device_id"]
    proxy_url = stats.proxy
    tag = stats.name

    proxy_tag = f" [proxy]" if proxy_url else "[direct]"
    print(f"[{tag}] Mining | {wallet[:20]}... | {device_id[:20]}... {proxy_tag}")

    while True:
        session_id = gen_session_id()
        print(f"[{tag}] Token gen {stats.token_gen + 1}...")

        try:
            token_data = await fetch_ws_token(wallet, session_id, device_id, stats.token_gen, fp, proxy_url)
            token = token_data["token"]
            ws_url = token_data.get("wsUrl", POOL_WS)
            stats.token_gen += 1
        except Exception as e:
            print(f"[{tag}] Token failed: {e}")
            await asyncio.sleep(30)
            continue

        full_ws_url = f"{ws_url}?token={token}&session={session_id}&device={device_id}"

        try:
            ws_kwargs = {
                "origin": "https://mining.thejaynetwork.com",
                "additional_headers": {"User-Agent": fp["ua"]},
                "ping_interval": None, "ping_timeout": None, "close_timeout": 5,
            }
            # websockets uses 'extra_headers' for proxy auth if needed
            if proxy_url:
                ws_kwargs["proxy"] = proxy_url

            async with websockets.connect(full_ws_url, **ws_kwargs) as ws:
                stats.connected = True
                print(f"[{tag}] Connected!")

                await ws.send(json.dumps({
                    "type": "auth",
                    "payload": {"wallet": wallet, "sessionId": session_id,
                                "deviceId": device_id, "fingerprint": fp["fingerprint"]}
                }))

                heartbeat_task = asyncio.create_task(heartbeat_loop(ws, session_id, device_id))
                share_count = 0
                share_task = None

                try:
                    async for raw_msg in ws:
                        try:
                            msg = json.loads(raw_msg)
                        except:
                            continue

                        msg_type = msg.get("type", "")
                        data = msg.get("payload", msg.get("data", {}))

                        if msg_type == "auth_success":
                            mid = data.get("minerId") or ""
                            if mid: stats.miner_id = mid
                            print(f"[{tag}] Auth OK | minerId={mid[:16] if mid else 'N/A'}")
                            await ws.send(json.dumps({
                                "type": "start_mining",
                                "payload": {
                                    "wallet": wallet, "threads": THREADS,
                                    "sessionId": session_id, "deviceId": device_id,
                                    "minerId": mid or None, "isJayWalletBrowser": False,
                                    "captchaToken": make_captcha_token(wallet),
                                    "tokenGeneration": stats.token_gen,
                                    "clientFingerprint": fp["fingerprint"],
                                }
                            }))

                        elif msg_type == "mining_started":
                            mid = data.get("minerId") or ""
                            if mid: stats.miner_id = mid
                            stats.mining = True
                            print(f"[{tag}] Mining started!")

                        elif msg_type == "new_work":
                            stats.current_job_id = data.get("jobId", "")
                            stats.current_difficulty = data.get("difficulty", 1_000_000)
                            stats.step += 1
                            if share_task is None or share_task.done():
                                share_task = asyncio.create_task(submit_shares(ws, stats, session_id, device_id))

                        elif msg_type == "share_accepted":
                            stats.shares_accepted += 1
                            share_count += 1
                            print(f"[{tag}] Share #{share_count} OK (total: {stats.shares_accepted})")
                            if share_count >= SHARES_BEFORE_REFRESH:
                                break

                        elif msg_type == "share_rejected":
                            stats.shares_rejected += 1

                        elif msg_type == "mining_reward":
                            amount = float(data.get("amount", 0))
                            stats.rewards_earned += amount
                            print(f"[{tag}] Reward! +{amount:.6f} JAY")

                        elif msg_type == "block_found":
                            stats.blocks_found += 1
                            print(f"[{tag}] BLOCK FOUND!")

                        elif msg_type == "payout_sent":
                            amount = float(data.get("amount", 0))
                            print(f"[{tag}] Payout: {amount:.6f} JAY")

                        elif msg_type in ("session_expired", "token_expired", "force_reconnect"):
                            break

                        elif msg_type == "error":
                            if data.get("code") in ("SESSION_CONFLICT", "DEVICE_CONFLICT"):
                                break

                except websockets.ConnectionClosed:
                    pass
                finally:
                    heartbeat_task.cancel()
                    if share_task and not share_task.done():
                        share_task.cancel()
                    try:
                        await heartbeat_task
                    except asyncio.CancelledError:
                        pass

        except Exception as e:
            print(f"[{tag}] WS error: {e}")

        stats.connected = False
        stats.mining = False
        await asyncio.sleep(random.uniform(3, 8))


async def dashboard_loop(all_stats):
    await asyncio.sleep(30)
    while True:
        print(f"\n{'='*70}")
        print(f"  Mining Dashboard — {time.strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        for st in all_stats:
            elapsed = time.time() - (st.start_time or time.time())
            h, m, s = int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)
            icon = "🟢" if st.mining else ("🟡" if st.connected else "🔴")
            px = "P" if st.proxy else "D"
            print(f"  {icon} {st.name:20s} {h:02d}:{m:02d}:{s:02d} | "
                  f"Sent:{st.shares_submitted:4d} OK:{st.shares_accepted:4d} | "
                  f"HR:{format_hashrate(st.hashrate):>10s} | "
                  f"Earned:{st.rewards_earned:.6f} JAY [{px}]")
        print(f"{'='*70}")
        await asyncio.sleep(30)


async def main():
    if not os.path.exists(MNEMONIC_FILE):
        print(f"❌ {MNEMONIC_FILE} not found")
        print("Format: 1 line = 1 BIP39 mnemonic")
        return

    with open(MNEMONIC_FILE) as f:
        mnemonics = [line.strip() for line in f if line.strip()]

    if not mnemonics:
        print(f"No mnemonics in {MNEMONIC_FILE}")
        return

    miners = []
    for i, mnemonic in enumerate(mnemonics):
        fp = gen_fingerprint(i)
        proxy_url = get_proxy(i)
        try:
            wallet = mnemonic_to_jay_wallet(mnemonic)
            word_count = len(mnemonic.split())
            name = f"wallet_{i+1}_{word_count}w"
            proxy_tag = f" [proxy]" if proxy_url else " [direct]"
            print(f"  [{i+1}] {name:20s} → {wallet}{proxy_tag}")
            stats = MinerStats(name, wallet, fp, proxy_url)
            stats.start_time = time.time()
            miners.append(stats)
        except Exception as e:
            print(f"  [{i+1}] ❌ Invalid mnemonic: {e}")

    if not miners:
        print("No valid wallets")
        return

    print(f"\nStarting {len(miners)} miner(s)...\n")

    for st in miners:
        balance = await check_balance(st.wallet, st.proxy)
        st.balance = balance
        history = await check_history(st.wallet, st.proxy)
        hist_total = sum(float(h.get("jay", h.get("amount", 0))) for h in history)
        print(f"  {st.name}: {balance:.6f} JAY | History: {len(history)} records, ~{hist_total:.6f}")

    print(f"\nMining...\n")
    tasks = [mining_loop(st) for st in miners] + [dashboard_loop(miners)]
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMining stopped.")
