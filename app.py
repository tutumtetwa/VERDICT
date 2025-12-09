from flask import Flask, render_template, request, jsonify
import spam_engine
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

spam_engine.train()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    text_to_scan = request.form.get('message', '')
    sender = request.form.get('sender', '')
    
    if 'screenshot' in request.files:
        file = request.files['screenshot']
        if file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            extracted_text = spam_engine.extract_text_from_image(filepath)
            text_to_scan += "\n" + extracted_text
            os.remove(filepath)

    if not text_to_scan.strip():
        return jsonify({'error': "No text provided."})

    # AI Prediction
    verdict, confidence = spam_engine.predict_text_ml(text_to_scan)
    
    # Forensics
    urls, link_risks = spam_engine.analyze_links(text_to_scan)
    sender_risks = spam_engine.analyze_sender(sender)
    
    # Check text body for homoglyphs
    homo_risks = spam_engine.detect_homoglyphs(text_to_scan)
    
    all_alerts = link_risks + sender_risks + homo_risks
    
    # Force SPAM verdict if critical risks found
    critical_triggers = ["Homoglyph Detected", "Burner Phone", "Geo Alert", "IP URL"]
    for alert in all_alerts:
        if any(trig in alert for trig in critical_triggers):
            if verdict == "SAFE":
                verdict = "SPAM"
                confidence = 95.5

    return jsonify({
        'verdict': verdict,
        'confidence': confidence,
        'urls_found': urls,
        'alerts': all_alerts,
        'scanned_text': text_to_scan[:500]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)