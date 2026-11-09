# VERDICT: Phishing & SMS Scam Detector

**Live:** https://verdict-scanner-chi.vercel.app (click **Try a sample scam message**)

Paste a suspicious email or text and VERDICT returns a verdict, a confidence score and the forensic evidence behind it.

## How it works
1. **Machine-learning classifier:** TF-IDF features feeding a Multinomial Naive Bayes model, trained on the 5,574-message [SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) at startup
2. **Link forensics:** expands shortened URLs hop by hop, geolocates the final host and flags raw-IP links and high-risk hosting regions
3. **Homoglyph detection:** catches look-alike Cyrillic and Greek letters hidden in words and domains (`pаypal.com`)
4. **Sender analysis:** free-mail providers, invalid phone numbers and VoIP/burner carriers (via `phonenumbers`)
5. **OCR (local only):** extracts text from screenshots with Tesseract. It's turned off automatically on hosts without the binary.

Critical forensic hits (homoglyphs, burner numbers, raw-IP links) override a "safe" model prediction.

## Security notes
- User-derived text is HTML-escaped before it's rendered
- URL expansion refuses private, loopback and link-local addresses on every redirect hop (SSRF guard)
- 5 MB upload limit. Uploads go to temp files and are deleted immediately. Nothing is stored.

## Stack
Python · Flask · scikit-learn · pandas · tldextract · phonenumbers · deployed on Vercel

## Run locally
```bash
pip install -r requirements.txt
python app.py      # http://localhost:5000
```

Built by Tutu Mtetwa & Tate Nyoni (CS 455 final project).
