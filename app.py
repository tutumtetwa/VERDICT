import os
import tempfile

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

import spam_engine

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB uploads
MAX_TEXT = 10_000
ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

spam_engine.train()
OCR_ENABLED = spam_engine.ocr_available()


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp


@app.route("/")
def home():
    return render_template("index.html", ocr_enabled=OCR_ENABLED)


@app.route("/robots.txt")
def robots():
    body = f"User-agent: *\nAllow: /\nSitemap: {request.url_root}sitemap.xml\n"
    return app.response_class(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"<url><loc>{request.url_root}</loc></url></urlset>"
    )
    return app.response_class(body, mimetype="application/xml")


@app.route("/health")
def health():
    return jsonify(status="ok", ocr=OCR_ENABLED)


@app.route("/analyze", methods=["POST"])
def analyze():
    text_to_scan = request.form.get("message", "")[:MAX_TEXT]
    sender = request.form.get("sender", "")

    file = request.files.get("screenshot")
    if file and file.filename:
        if not OCR_ENABLED:
            if not text_to_scan.strip():
                return jsonify(error="Screenshot scanning isn't available on this server. Paste the message text instead.")
        else:
            ext = os.path.splitext(secure_filename(file.filename))[1].lower()
            if ext not in ALLOWED_IMAGE_EXT:
                return jsonify(error="Unsupported image type."), 400
            with tempfile.NamedTemporaryFile(suffix=ext) as tmp:
                file.save(tmp.name)
                text_to_scan += "\n" + spam_engine.extract_text_from_image(tmp.name)

    if not text_to_scan.strip():
        return jsonify(error="No text provided.")

    verdict, confidence = spam_engine.predict_text_ml(text_to_scan)
    urls, link_risks = spam_engine.analyze_links(text_to_scan)
    all_alerts = link_risks + spam_engine.analyze_sender(sender) + spam_engine.detect_homoglyphs(text_to_scan)

    critical = ["Homoglyph Detected", "Burner Phone", "Geo Alert", "IP URL"]
    if verdict == "SAFE" and any(t in a for a in all_alerts for t in critical):
        verdict, confidence = "SPAM", 95.5

    return jsonify(verdict=verdict, confidence=confidence, urls_found=urls, alerts=all_alerts)


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="File too large (max 5 MB)."), 413


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
