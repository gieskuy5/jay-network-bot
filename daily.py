#!/usr/bin/env python3
"""
Jay Network Campaign — Multi-Account HTTP Script
Auth: auth.txt (1 line = 1 JWT token)
Proxy: proxy.txt (1 line = 1 proxy, supports http/https/socks4/socks5)
"""

import requests
import json
import sys
import time
import random
import hashlib
import uuid
import os
from datetime import datetime

BASE = "https://campaign.thejaynetwork.com"
DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_FILE = os.path.join(DIR, "auth.txt")
PROXY_FILE = os.path.join(DIR, "proxy.txt")

# ─── Proxy Loader ──────────────────────────────────────────────

def load_proxies():
    """Load proxies from proxy.txt. Supports http/https/socks4/socks5 formats:
    http://host:port
    http://user:pass@host:port
    socks5://host:port
    socks4://host:port
    host:port          (treated as http)
    user:pass@host:port (treated as http)
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


def get_proxy(index, proxy_list):
    """Get proxy dict for requests library. Returns None if no proxies."""
    if not proxy_list:
        return None
    proxy_url = proxy_list[index % len(proxy_list)]
    return {"http": proxy_url, "https": proxy_url}


PROXIES = load_proxies()
if PROXIES:
    print(f"Loaded {len(PROXIES)} proxy(ies)")

# ─── Fingerprint Generator ─────────────────────────────────────

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

SCREENS = [
    "1920x1080", "2560x1440", "1366x768", "1536x864", "1440x900",
    "1680x1050", "1280x720", "2560x1600", "3840x2160", "1920x1200",
]

TIMEZONES = [
    "Asia/Jakarta", "Asia/Makassar", "Asia/Jayapura", "America/New_York",
    "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Asia/Tokyo",
    "Asia/Singapore", "Australia/Sydney",
]

LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
]


def gen_fingerprint(index):
    ua = USER_AGENTS[index % len(USER_AGENTS)]
    screen = SCREENS[index % len(SCREENS)]
    tz = TIMEZONES[index % len(TIMEZONES)]
    lang = LANGUAGES[index % len(LANGUAGES)]
    device_id = f"device_{hashlib.md5(f'jay_{index}'.encode()).hexdigest()[:16]}"
    fp_hash = hashlib.sha256(f"{ua}{screen}{tz}{device_id}".encode()).hexdigest()[:32]
    return {"ua": ua, "screen": screen, "tz": tz, "lang": lang, "device_id": device_id, "fingerprint": fp_hash}


# ─── Account Class ─────────────────────────────────────────────

class Account:
    def __init__(self, token, index):
        self.token = token.strip()
        self.index = index
        self.fp = gen_fingerprint(index)
        self.proxy = get_proxy(index, PROXIES)
        self.name = f"account_{index+1}"
        self.email = ""

        self.headers = {
            "Cookie": f"__Secure-next-auth.session-token={self.token}",
            "Content-Type": "application/json",
            "User-Agent": self.fp["ua"],
            "Accept-Language": self.fp["lang"],
            "Referer": f"{BASE}/dashboard",
            "Origin": BASE,
            "X-Client-Fingerprint": self.fp["fingerprint"],
            "X-Device-ID": self.fp["device_id"],
        }

        self._init_session()

    def _init_session(self):
        try:
            d = self.api("GET", "/api/auth/session")
            u = d.get("user", {})
            self.name = u.get("name", f"account_{self.index+1}")
            self.email = u.get("email", "")
        except:
            pass

    def api(self, method, path, data=None, extra_headers=None):
        h = {**self.headers, **(extra_headers or {})}
        r = requests.request(method, f"{BASE}{path}", headers=h, json=data,
                             proxies=self.proxy, timeout=15)
        try:
            return r.json()
        except:
            return {"error": r.text[:200], "status": r.status_code}

    def check_session(self):
        d = self.api("GET", "/api/auth/session")
        u = d.get("user", {})
        if u.get("email"):
            return True, u
        return False, {}

    def get_tasks(self):
        d = self.api("GET", "/api/dashboard-data")
        if not d.get("success"):
            return []
        return d.get("tasks", [])

    def daily_status(self):
        d = self.api("GET", "/api/daily-login")
        return d.get("data", {})

    def claim_daily(self, day=None):
        if day is None:
            status = self.daily_status()
            day = status.get("currentDay", 14)
            if status.get("claimedToday"):
                return "already_claimed"
            if not status.get("campaignActive"):
                return "campaign_ended"
        d = self.api("POST", "/api/daily-login", {"day": day})
        return "ok" if d.get("success") else d.get("error", "failed")

    def complete_task(self, task_id, proof=""):
        d = self.api("POST", "/api/task/complete", {"taskId": task_id, "proof": proof})
        return d.get("success", False), d.get("error", "")

    def referral_info(self):
        d = self.api("GET", "/api/referral")
        return d.get("data", {})

    def dashboard_summary(self):
        tasks = self.get_tasks()
        done = [t for t in tasks if t["status"] == "completed"]
        earned = sum(t["reward"] for t in done)
        total = sum(t["reward"] for t in tasks)
        return len(done), len(tasks), earned, total


# ─── Load Accounts ─────────────────────────────────────────────

def load_accounts():
    if not os.path.exists(AUTH_FILE):
        print(f"❌ {AUTH_FILE} not found")
        return []

    with open(AUTH_FILE) as f:
        tokens = [line.strip() for line in f if line.strip()]

    accounts = []
    for i, token in enumerate(tokens):
        acc = Account(token, i)
        if acc.email:
            proxy_info = acc.proxy["http"] if acc.proxy else "direct"
            accounts.append(acc)
        else:
            print(f"  ⚠️ Token #{i+1} invalid or expired, skipping")
    return accounts


# ─── Multi-Account Functions ───────────────────────────────────

def check_all(accounts):
    print(f"\n{'='*60}")
    print(f"🔍 Session Check — {datetime.now():%Y-%m-%d %H:%M}")
    print(f"{'='*60}")

    for acc in accounts:
        ok, user = acc.check_session()
        proxy_tag = f" [proxy]" if acc.proxy else ""
        if ok:
            done, total, earned, max_earn = acc.dashboard_summary()
            print(f"  ✅ {acc.name:20s} {acc.email:30s} {done}/{total} tasks | {earned} JAY{proxy_tag}")
        else:
            print(f"  ❌ {acc.name:20s} SESSION EXPIRED{proxy_tag}")


def checkin_all(accounts):
    print(f"\n{'='*60}")
    print(f"🔄 Daily Check-in — {datetime.now():%Y-%m-%d %H:%M}")
    print(f"{'='*60}")

    for acc in accounts:
        proxy_tag = f" [proxy: {acc.proxy['http'][:30]}...]" if acc.proxy else "[direct]"
        print(f"\n── {acc.name} ({acc.email}) {proxy_tag} ──")
        print(f"   UA: {acc.fp['ua'][:50]}...")
        print(f"   Device: {acc.fp['device_id'][:30]}...")

        ok, user = acc.check_session()
        if not ok:
            print(f"   ❌ Session expired, skipping")
            continue

        print(f"   ✅ {user.get('email','')}")

        result = acc.claim_daily()
        if result == "ok":
            print(f"   🎁 Daily claimed!")
        elif result == "already_claimed":
            print(f"   📅 Already claimed today")
        elif result == "campaign_ended":
            print(f"   ⚠️ Campaign ended")
        else:
            print(f"   ❌ Daily: {result}")

        tasks = acc.get_tasks()
        pending = [t for t in tasks if t["status"] == "pending" and t["verifyType"] == "api"]
        completed = 0

        for t in pending:
            ok, err = acc.complete_task(t["id"], f"auto:{t['category']}")
            if ok:
                completed += 1
                print(f"   ✅ {t['title']}")
            time.sleep(3)

        done, total, earned, max_earn = acc.dashboard_summary()
        print(f"   📊 {done}/{total} tasks | {earned}/{max_earn} JAY | +{completed} new")


def complete_all_pending(accounts):
    print(f"\n{'='*60}")
    print(f"⚡ Complete All Pending — {datetime.now():%Y-%m-%d %H:%M}")
    print(f"{'='*60}")

    for acc in accounts:
        print(f"\n── {acc.name} ({acc.email}) ──")
        ok, user = acc.check_session()
        if not ok:
            print(f"   ❌ Session expired")
            continue

        tasks = acc.get_tasks()
        pending = [t for t in tasks if t["status"] == "pending"]

        for t in pending:
            if t["verifyType"] == "api":
                ok, err = acc.complete_task(t["id"], f"auto:{t['category']}")
                status = "✅" if ok else f"❌ {err}"
                print(f"   {status} {t['title']}")
                time.sleep(5)
            else:
                print(f"   ⏭️ {t['title']} ({t['verifyType']})")

        done, total, earned, max_earn = acc.dashboard_summary()
        print(f"   📊 {done}/{total} tasks | {earned}/{max_earn} JAY")


def status_all(accounts):
    print(f"\n{'='*60}")
    print(f"📊 All Accounts — {datetime.now():%Y-%m-%d %H:%M}")
    print(f"{'='*60}")

    for acc in accounts:
        proxy_tag = f" [proxy]" if acc.proxy else " [direct]"
        print(f"\n── {acc.name} ({acc.email}){proxy_tag} ──")
        print(f"   FP: {acc.fp['fingerprint'][:16]}... | UA: {acc.fp['ua'][:50]}...")

        ok, user = acc.check_session()
        if not ok:
            print(f"   ❌ Session expired")
            continue

        done, total, earned, max_earn = acc.dashboard_summary()
        pending = [t for t in acc.get_tasks() if t["status"] == "pending"]
        print(f"   📊 {done}/{total} tasks | {earned}/{max_earn} JAY | {len(pending)} pending")

        ref = acc.referral_info()
        print(f"   🔗 Referral: {ref.get('referralCode', 'N/A')} | {ref.get('referralCount', 0)} refs")


# ─── Main ──────────────────────────────────────────────────────

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "checkin"

    accounts = load_accounts()
    if not accounts:
        print("No valid tokens in auth.txt")
        sys.exit(1)

    print(f"Loaded {len(accounts)} account(s)")

    cmds = {
        "checkin": lambda: checkin_all(accounts),
        "check": lambda: check_all(accounts),
        "complete": lambda: complete_all_pending(accounts),
        "status": lambda: status_all(accounts),
    }

    if cmd in cmds:
        cmds[cmd]()
    else:
        print(f"Usage: python3 {sys.argv[0]} [checkin|check|complete|status]")
