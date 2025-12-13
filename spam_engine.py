import pandas as pd
import requests
import io
import os
import pickle
import re
import tldextract
import pytesseract
import socket
import phonenumbers
from phonenumbers import geocoder, carrier
from PIL import Image
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

MODEL_FILE = "spam_detector_v3.pkl"
DATASET_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"

# --- 1. CORE ML TRAINING ---
def get_data():
    if os.path.exists(MODEL_FILE): return None 
    try:
        s = requests.get(DATASET_URL).content
        df = pd.read_csv(io.StringIO(s.decode('utf-8')), sep='\t', header=None, names=['label', 'message'])
        df['label_num'] = df.label.map({'ham': 0, 'spam': 1})
        return df
    except: return None

def train():
    df = get_data()
    if df is None and os.path.exists(MODEL_FILE): return
    X_train, X_test, y_train, y_test = train_test_split(df['message'], df['label_num'], test_size=0.2)
    pipeline = Pipeline([('tfidf', TfidfVectorizer(stop_words='english')), ('clf', MultinomialNB())])
    pipeline.fit(X_train, y_train)
    pickle.dump(pipeline, open(MODEL_FILE, 'wb'))

def predict_text_ml(text):
    if not os.path.exists(MODEL_FILE): train()
    model = pickle.load(open(MODEL_FILE, 'rb'))
    prediction = model.predict([text])[0]
    proba = model.predict_proba([text])[0]
    return ("SPAM" if prediction == 1 else "SAFE"), round(proba[prediction]*100, 2)

# --- 2. OCR ---
def extract_text_from_image(image_path):
    try:
        text = pytesseract.image_to_string(Image.open(image_path))
        return text.strip()
    except: return ""

# --- 3. HOMOGLYPH DETECTOR (FIXED & TUNED) ---
def detect_homoglyphs(text):
    """
    Smarter detection: Only flags if a word mixes Latin characters with 
    specific 'imposter' scripts (Cyrillic, Greek) often used in attacks.
    Ignores common symbols, punctuation, and emojis.
    """
    risks = []
    
    # Regex for dangerous scripts often used to fake English
    # Cyrillic: \u0400-\u04FF
    # Greek: \u0370-\u03FF
    dangerous_pattern = re.compile(r'[\u0400-\u04FF\u0370-\u03FF]')
    
    # Regex for standard English (Latin)
    latin_pattern = re.compile(r'[a-zA-Z]')

    for word in text.split():
        # Only analyze if the word looks like it SHOULD be English
        if latin_pattern.search(word):
            # Check if it ALSO contains dangerous foreign letters
            if dangerous_pattern.search(word):
                risks.append(f"🅰️ <b>Homoglyph Detected:</b> The word '{word}' contains hidden Cyrillic/Greek characters. This is a common phishing tactic.")
                
    return risks

# --- 4. PHONE FORENSICS ---
def analyze_phone(number_str):
    risks = []
    try:
        parsed = phonenumbers.parse(number_str, None)
        if not phonenumbers.is_valid_number(parsed):
            return [f"⚠️ <b>Invalid Number:</b> {number_str} does not match global telecom standards."]

        loc = geocoder.description_for_number(parsed, "en")
        car = carrier.name_for_number(parsed, "en")
        
        info = f"ℹ️ <b>Phone Scan:</b> {loc} | Carrier: {car if car else 'Unknown'}"
        risks.append(info)

        suspicious_carriers = ['Google', 'Twilio', 'Bandwidth', 'Skype', 'Vonage', 'TextNow']
        if car and any(scam in car for scam in suspicious_carriers):
            risks.append(f"🚨 <b>Burner Phone Risk:</b> Number belongs to '{car}' (VoIP). High likelihood of scammer.")

    except: pass
    return risks

# --- 5. LINK & GEO ANALYSIS ---
def get_geo_location(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response['status'] == 'success':
            return f"{response['country']}, {response['city']}", response['country']
    except: pass
    return "Unknown", "Unknown"

def expand_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.head(url, allow_redirects=True, headers=headers, timeout=3)
        return response.url
    except: return url

def analyze_links(text):
    urls = re.findall(r'(https?://\S+)', text)
    risks = []
    final_urls = []
    
    for url in urls:
        real_url = expand_url(url)
        ext = tldextract.extract(real_url)
        domain = f"{ext.domain}.{ext.suffix}"
        location, country = get_geo_location(domain)
        
        final_urls.append(f"{url} <br>⬇️ <br><b>{real_url}</b> <br>🌍 <b>{location}</b>")
        
        # Check domain specifically for homoglyphs
        homo_alerts = detect_homoglyphs(domain)
        risks.extend(homo_alerts)

        high_risk = ['Russia', 'China', 'North Korea', 'Iran', 'Nigeria']
        if country in high_risk:
            risks.append(f"🚩 <b>Geo Alert:</b> Server hosted in {country}.")

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', real_url):
            risks.append(f"⚠️ <b>IP URL:</b> {real_url} (Phishing Risk)")

    return final_urls, risks

# --- 6. SENDER ANALYSIS ---
def analyze_sender(sender):
    sender = sender.strip()
    risks = []
    if not sender: return []

    if re.match(r'^[\+\d\-\(\)\s]+$', sender) and len(re.sub(r'\D', '', sender)) > 6:
        return analyze_phone(sender)
    
    sender = sender.lower()
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    if '@' in sender:
        domain = sender.split('@')[-1]
        if domain in free_providers:
            risks.append(f"ℹ️ <b>Free Provider:</b> Sender using {domain}.")
        
        risks.extend(detect_homoglyphs(sender))
            
    return risks

if __name__ == "__main__":
    train()