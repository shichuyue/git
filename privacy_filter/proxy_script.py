"""
隐私流量拦截代理 - mitmproxy 插件
功能：
1. 黑名单域名拦截广告/统计埋点
2. 随机伪装UA、删除追踪请求头
3. 过滤第三方跨站追踪Cookie
4. 实时流量日志审计
"""
import json
import logging
import random
import os
from datetime import datetime

from mitmproxy import http
from mitmproxy import ctx

# ============================================================
# 配置
# ============================================================

# 用户代理池 - 每次请求随机挑选
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

# 追踪请求头 - 全部清除
TRACKING_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Requested-With", "X-Request-Id", "X-Client-Data", "X-Do-Not-Track",
    "DNT", "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform",
    "Sec-CH-UA-Platform-Version", "Sec-CH-UA-Arch", "Sec-CH-UA-Model",
    "Sec-CH-UA-Full-Version-List", "Sec-CH-Prefers-Color-Scheme",
    "Sec-CH-Prefers-Reduced-Motion", "Sec-Fetch-Site", "Sec-Fetch-Mode",
    "Sec-Fetch-Dest", "Sec-Fetch-User", "Sec-GPC", "Referer", "Via",
    "X-Correlation-ID", "X-Trace-ID", "X-Amzn-Trace-Id",
    "True-Client-IP", "X-Originating-IP", "X-Cluster-Client-IP",
]

# Cookie 清理关键词 - 第三方追踪Cookie
TRACKING_COOKIE_PATTERNS = [
    "_ga", "_gid", "_gat",           # Google Analytics
    "_fbp", "_fbc",                  # Facebook Pixel
    "_hjSession", "_hjSessionUser",  # Hotjar
    "_gcl_au",                       # Google Ads
    "_rdt_uuid",                     # Reddit
    "_tt_enable_cookie",             # TikTok
    "_pin_unauth",                   # Pinterest
    "AMP_TOKEN",                     # AMP
    "_ym_uid", "_ym_d",              # Yandex
    "ajs_anonymous_id",             # Segment
    "__tld__", "_gaexp",            # Google Optimize
    "UID", "UIDR",                  # Scorecard Research
    "NID",                           # Google (tracking)
    "1P_JAR",                       # Google
    "CONSENT",                       # Google consent
    "OTZ",                           # Google Analytics
]

# 日志文件
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
RULES_DIR = os.path.join(BASE_DIR, "rules")
BLACKLIST_FILE = os.path.join(RULES_DIR, "blacklist.txt")
WHITELIST_FILE = os.path.join(RULES_DIR, "whitelist.txt")


def _setup_logging():
    """初始化日志配置"""
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_path = os.path.join(LOGS_DIR, "proxy.log")
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger = logging.getLogger("privacy_filter")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


def _load_domain_list(filepath):
    """从文本文件加载域名列表，每行一个"""
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f
                if line.strip() and not line.strip().startswith("#")}


def _should_block(host, blacklist, whitelist):
    """判断是否应该拦截该域名"""
    host = host.lower()
    for w in whitelist:
        if host == w or host.endswith("." + w):
            return False
    for b in blacklist:
        if host == b or host.endswith("." + b):
            return True
    return False


class PrivacyFilter:
    """隐私流量拦截代理插件"""

    def __init__(self):
        self.logger = _setup_logging()
        self.blacklist = set()
        self.whitelist = set()
        self.stats = {
            "total": 0, "blocked": 0, "ua_masked": 0,
            "headers_cleaned": 0, "cookies_filtered": 0,
        }
        self._reload_rules()
        self.logger.info("PrivacyFilter addon loaded")

    def _reload_rules(self):
        self.blacklist = _load_domain_list(BLACKLIST_FILE)
        self.whitelist = _load_domain_list(WHITELIST_FILE)
        self.logger.info(f"Loaded {len(self.blacklist)} blacklisted domains")

    def request(self, flow: http.HTTPFlow):
        self.stats["total"] += 1
        host = flow.request.pretty_host

        if _should_block(host, self.blacklist, self.whitelist):
            self.stats["blocked"] += 1
            self._log(flow, "BLOCK")
            flow.response = http.Response.make(
                403,
                b"<h1>Blocked by Privacy Filter</h1>"
                b"<p>This domain is in the privacy filter blacklist.</p>",
                {"Content-Type": "text/html; charset=utf-8"}
            )
            return

        flow.request.headers["User-Agent"] = random.choice(USER_AGENTS)
        self.stats["ua_masked"] += 1

        cleaned = False
        for header in TRACKING_HEADERS:
            if header in flow.request.headers:
                del flow.request.headers[header]
                cleaned = True
        if cleaned:
            self.stats["headers_cleaned"] += 1

        self._clean_cookies(flow)
        self._log(flow, "PASS")

    def response(self, flow: http.HTTPFlow):
        if "Set-Cookie" in flow.response.headers:
            self._clean_response_cookies(flow)

    def _clean_cookies(self, flow: http.HTTPFlow):
        if "Cookie" not in flow.request.headers:
            return
        raw_cookie = flow.request.headers["Cookie"]
        cookies = [c.strip() for c in raw_cookie.split(";")]
        filtered = []
        fc = 0
        for cookie in cookies:
            name = cookie.split("=")[0].strip() if "=" in cookie else cookie
            if any(name.startswith(p) or name == p for p in TRACKING_COOKIE_PATTERNS):
                fc += 1
            else:
                filtered.append(cookie)
        if fc > 0:
            self.stats["cookies_filtered"] += 1
            if filtered:
                flow.request.headers["Cookie"] = "; ".join(filtered)
            else:
                del flow.request.headers["Cookie"]

    def _clean_response_cookies(self, flow: http.HTTPFlow):
        set_cookies = flow.response.headers.get_all("Set-Cookie")
        kept = []
        for sc in set_cookies:
            name = sc.split("=")[0].strip()
            if any(name.startswith(p) or name == p for p in TRACKING_COOKIE_PATTERNS):
                continue
            kept.append(sc)
        flow.response.headers.set_all("Set-Cookie", kept)

    def _log(self, flow: http.HTTPFlow, action: str):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "scheme": flow.request.scheme,
            "status": flow.response.status_code if flow.response else 0,
        }
        line = json.dumps(entry, ensure_ascii=False)
        self.logger.info(line)
        realtime_log = os.path.join(LOGS_DIR, "realtime.jsonl")
        try:
            with open(realtime_log, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


addons = [PrivacyFilter()]
