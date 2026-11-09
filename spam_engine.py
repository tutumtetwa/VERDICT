"""VERDICT detection engine: a Naive Bayes text classifier plus forensic heuristics
(homoglyphs, link expansion, hosting geography, sender and phone checks).

All strings returned for display are HTML-escaped here, because the front end
renders alert and link entries as HTML.
"""
import ipaddress
import os
import re
import socket
from html import escape
from urllib.parse import urljoin, urlparse

import pandas as pd
import phonenumbers
import requests
import tldextract
from phonenumbers import carrier, geocoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "data", "sms.tsv")  # SMS Spam Collection (UCI)

# Offline suffix list so tldextract never writes a cache to a read-only filesystem.
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_model = None

MAX_URLS = 5
MAX_REDIRECTS = 5


# --- 1. CORE ML ---
def train():
    """Train the TF-IDF + Multinomial Naive Bayes pipeline in memory (about a second)."""
    global _model
    df = pd.read_csv(DATASET_PATH, sep="\t", header=None, names=["label", "message"])
    y = df.label.map({"ham": 0, "spam": 1})
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(stop_words="english")),
        ("clf", MultinomialNB()),
    ])
    pipeline.fit(df["message"], y)
    _model = pipeline
    return pipeline


def predict_text_ml(text):
    model = _model or train()
    prediction = int(model.predict([text])[0])
    proba = model.predict_proba([text])[0]
    return ("SPAM" if prediction == 1 else "SAFE"), round(float(proba[prediction]) * 100, 2)


# --- 2. OCR (needs the Tesseract binary; unavailable on serverless hosts) ---
def ocr_available():
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def extract_text_from_image(image_path):
    try:
        import pytesseract
        from PIL import Image
        return pytesseract.image_to_string(Image.open(image_path)).strip()
    except Exception:
        return ""


# --- 3. HOMOGLYPH DETECTOR ---
_DANGEROUS = re.compile(r"[Ѐ-ӿͰ-Ͽ]")  # Cyrillic, Greek
_LATIN = re.compile(r"[a-zA-Z]")


def detect_homoglyphs(text):
    """Flag words that mix Latin letters with look-alike Cyrillic/Greek letters."""
    risks = []
    for word in text.split():
        if _LATIN.search(word) and _DANGEROUS.search(word):
            risks.append(
                f"🅰️ <b>Homoglyph Detected:</b> The word '{escape(word[:80])}' contains hidden "
                "Cyrillic/Greek characters. This is a common phishing tactic."
            )
    return risks


# --- 4. PHONE FORENSICS ---
SUSPICIOUS_CARRIERS = ["Google", "Twilio", "Bandwidth", "Skype", "Vonage", "TextNow"]


def analyze_phone(number_str):
    risks = []
    try:
        parsed = phonenumbers.parse(number_str, None)
        if not phonenumbers.is_valid_number(parsed):
            return [f"⚠️ <b>Invalid Number:</b> {escape(number_str)} does not match global telecom standards."]
        loc = geocoder.description_for_number(parsed, "en")
        car = carrier.name_for_number(parsed, "en")
        risks.append(f"ℹ️ <b>Phone Scan:</b> {escape(loc)} | Carrier: {escape(car) if car else 'Unknown'}")
        if car and any(s in car for s in SUSPICIOUS_CARRIERS):
            risks.append(
                f"🚨 <b>Burner Phone Risk:</b> Number belongs to '{escape(car)}' (VoIP). "
                "High likelihood of scammer."
            )
    except Exception:
        pass
    return risks


# --- 5. LINK & GEO ANALYSIS ---
def _public_ip(host):
    """Resolve host and return its IP only if every address is publicly routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return None
    ips = {info[4][0] for info in infos}
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            return None
    return next(iter(ips), None)


def expand_url(url):
    """Follow redirects one hop at a time, refusing private, loopback or link-local targets (SSRF guard)."""
    current = url
    for _ in range(MAX_REDIRECTS):
        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return current
        if _public_ip(parsed.hostname) is None:
            return current
        try:
            resp = requests.head(
                current, allow_redirects=False, timeout=3,
                headers={"User-Agent": "VERDICT-link-scanner/1.0"},
            )
        except requests.RequestException:
            return current
        location = resp.headers.get("Location")
        if resp.is_redirect and location:
            current = urljoin(current, location)
            continue
        return current
    return current


def get_geo_location(host):
    ip = _public_ip(host)
    if not ip:
        return "Unknown", "Unknown"
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if data.get("status") == "success":
            return f"{data.get('country')}, {data.get('city')}", data.get("country")
    except (requests.RequestException, ValueError):
        pass
    return "Unknown", "Unknown"


HIGH_RISK_COUNTRIES = ["Russia", "China", "North Korea", "Iran", "Nigeria"]
_IP_URL = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def analyze_links(text):
    urls = re.findall(r"(https?://\S+)", text)[:MAX_URLS]
    risks, final_urls = [], []
    for url in urls:
        real_url = expand_url(url)
        host = urlparse(real_url).hostname or ""
        ext = _tld(real_url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        location, country = get_geo_location(host)

        final_urls.append(
            f"{escape(url)} <br>⬇️ <br><b>{escape(real_url)}</b> <br>🌍 <b>{escape(location)}</b>"
        )
        risks.extend(detect_homoglyphs(domain))
        if country in HIGH_RISK_COUNTRIES:
            risks.append(f"🚩 <b>Geo Alert:</b> Server hosted in {escape(country)}.")
        if _IP_URL.match(host):
            risks.append(f"⚠️ <b>IP URL:</b> {escape(real_url)} (Phishing Risk)")
    return final_urls, risks


# --- 6. SENDER ANALYSIS ---
FREE_PROVIDERS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]


def analyze_sender(sender):
    sender = sender.strip()[:200]
    if not sender:
        return []
    if re.match(r"^[\+\d\-\(\)\s]+$", sender) and len(re.sub(r"\D", "", sender)) > 6:
        return analyze_phone(sender)
    risks = []
    sender = sender.lower()
    if "@" in sender:
        domain = sender.split("@")[-1]
        if domain in FREE_PROVIDERS:
            risks.append(f"ℹ️ <b>Free Provider:</b> Sender using {escape(domain)}.")
        risks.extend(detect_homoglyphs(sender))
    return risks
