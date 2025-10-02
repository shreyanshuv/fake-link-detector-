from flask import Flask, render_template, request
from dotenv import load_dotenv
import os, re, socket
from urllib.parse import urlparse
from datetime import datetime

load_dotenv()  # Load environment variables from .env file

# Optional Gemini
try:
    import google.generativeai as genai
    genai.configure(api_key="AIzaSyAH_1hZ3D_M3vJN_3i-7z7jhQS1bsQEnec")  # <-- Add this line here
except:
    genai = None

# Optional WHOIS
try:
    import whois
except:
    whois = None

app = Flask(__name__)

# --- Rule-based heuristics ---
SUSPICIOUS_TLDS = {"zip", "mov", "loan", "click", "country", "stream", "xyz", "top", "cf", "tk", "ml"}
URL_SHORTENERS = {"bit.ly", "goo.gl", "t.co", "tinyurl.com"}
SENSITIVE_KEYWORDS = {"verify", "login", "update", "secure", "account", "billing", "bank", "password"}
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)


def extract_parts(raw_url: str):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    host = parsed.netloc.split("@")[-1].split(":")[0]
    return parsed, host


def rule_checks(url: str):
    parsed, host = extract_parts(url)

    scheme_https = parsed.scheme.lower() == "https"
    contains_ip = bool(IPV4_RE.match(host))
    is_puny = bool(PUNYCODE_RE.search(host))
    tld = host.split(".")[-1].lower() if "." in host else ""
    tld_suspicious = tld in SUSPICIOUS_TLDS
    is_shortened = host.lower() in URL_SHORTENERS
    has_sensitive = any(k in url.lower() for k in SENSITIVE_KEYWORDS)

    score, reasons = 0, []
    def add(cond, pts, reason):
        nonlocal score
        if cond: score += pts; reasons.append(reason)

    add(not scheme_https, 1, "Not HTTPS")
    add(contains_ip, 2, "Contains IP instead of domain")
    add(is_puny, 2, "Punycode in domain")
    add(tld_suspicious, 1, f"Suspicious TLD .{tld}")
    add(is_shortened, 1, "Known shortener")
    add(has_sensitive, 1, "Sensitive keyword in URL")

    verdict = "Low Risk" if score == 1 else "Likely Safe"
    if score >= 5: verdict = "Likely Malicious"
    elif score >= 2: verdict = "Suspicious"

    return {"url": url, "host": host, "tld": tld, "score": score, "verdict": verdict, "reasons": reasons}


def gemini_analyze(result):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key: return "Gemini not configured."
    if genai is None: return "google-generativeai not installed."
    try:
        genai.configure(api_key=api_key)
        # Updated model name based on Gemini API docs
        model = genai.GenerativeModel("gemini-2.5-pro")
        prompt = f"Analyze this URL {result['url']} classified as {result['verdict']}. Reasons: {result['reasons']}."
        resp = model.generate_content(prompt)
        return getattr(resp, "text", "No response from Gemini.")
    except Exception as e:
        return f"Gemini error: {e}"


@app.route("/", methods=["GET", "POST"])
def index():
    result, ai_analysis = None, None
    if request.method == "POST":
        url = request.form.get("url", "")
        if url:
            result = rule_checks(url)
            ai_analysis = gemini_analyze(result)
    return render_template("index.html", result=result, ai_analysis=ai_analysis)


if __name__ == "__main__":
    app.run(debug=True)
