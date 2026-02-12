import asyncio
import threading
import requests
import os
import tempfile
import logging
from email import message_from_bytes
from flask import Flask, request, jsonify
from aiosmtpd.controller import Controller

# --- Import modules in modules file ---
from modules.static_analyzer import StaticAnalyzer
from modules.ml_classifier import RansomwareClassifier
from modules.decision_engine import DecisionEngine

# ==========================================
# LOGGING CONFIGURATION
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler("ransomguard.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("RansomGuard")

# ==========================================
# CONFIGURATION & INITIALIZATION
# ==========================================
class Config:
    QUARANTINE_DIR = "./quarantine"
    MODEL_PATH = "./models/ransomware_model.pkl"
    SCALER_PATH = "./models/scaler.pkl"
    GATEWAY_PORT = 10025
    API_PORT = 5000
    MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10 MB

os.makedirs(Config.QUARANTINE_DIR, exist_ok=True)

# Initialize Intelligence Modules
static_analyzer = StaticAnalyzer()
ml_classifier = RansomwareClassifier(Config.MODEL_PATH, Config.SCALER_PATH)
decision_engine = DecisionEngine()

# Try to load the ML model
try:
    ml_classifier.load_model()
    logger.info("ML model loaded successfully")
except Exception as e:
    logger.warning(f"ML model load failed: {e}. Falling back to static analysis only.")

# ==========================================
# PHASE 2: THE BRAIN (Flask API)
# ==========================================
app = Flask(__name__)

@app.route("/api/direct-scan", methods=["POST"])
def direct_scan():
    uploaded = request.files.get("file")
    if not uploaded:
        logger.warning("Direct scan requested with no file")
        return jsonify({"verdict": "ERROR", "reason": "No file uploaded"}), 400

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        uploaded.save(tmp.name)
        file_path = tmp.name

    logger.info(f"Brain received file for analysis: {uploaded.filename}")

    try:
        analysis = static_analyzer.analyze_file(file_path)

        if ml_classifier.is_trained:
            features = ml_classifier.prepare_features(analysis)
            prediction = ml_classifier.predict(features)
        else:
            prediction = {"confidence": 0, "label": "unknown"}

        decision = decision_engine.evaluate(
            analysis,
            prediction,
            {"filename": uploaded.filename}
        )

        logger.info(
            f"Decision made | File={uploaded.filename} | "
            f"Action={decision['action']} | "
            f"Confidence={prediction.get('confidence', 0)}"
        )

        return jsonify({
            "verdict": decision["action"],
            "confidence": prediction.get("confidence", 0),
            "reason": decision.get("reason", "Analysis completed")
        })

    except Exception as e:
        logger.error(f"Brain analysis error for {uploaded.filename}: {e}", exc_info=True)
        return jsonify({"verdict": "BLOCK", "reason": "Internal analysis error"}), 500

    finally:
        os.unlink(file_path)

def run_flask():
    logger.info(f"Brain API starting on 127.0.0.1:{Config.API_PORT}")
    app.run(host="127.0.0.1", port=Config.API_PORT, debug=False, use_reloader=False)

# ==========================================
# PHASE 1: THE GUARD (SMTP Gateway)
# ==========================================
class RansomwareGateway:
    async def handle_DATA(self, server, session, envelope):
        msg = message_from_bytes(envelope.content)
        logger.info("SMTP DATA received, inspecting message")

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get("Content-Disposition") is None:
                continue

            filename = part.get_filename()
            if not filename:
                continue

            payload = part.get_payload(decode=True)
            size = len(payload)

            logger.info(f"Intercepted attachment: {filename} ({size} bytes)")

            if size > Config.MAX_ATTACHMENT_SIZE:
                logger.warning(f"Attachment too large blocked: {filename}")
                return "554 Attachment exceeds size limit"

            try:
                response = requests.post(
                    f"http://127.0.0.1:{Config.API_PORT}/api/direct-scan",
                    files={"file": (filename, payload)},
                    timeout=60
                )

                if response.status_code != 200:
                    logger.error(f"Brain returned HTTP {response.status_code}")
                    return "451 Temporary scanning failure"

                result = response.json()
                if result.get("verdict") == "BLOCK":
                    logger.warning(
                        f"BLOCKED attachment | File={filename} | "
                        f"Confidence={result.get('confidence')}"
                    )
                    return "554 Malicious attachment detected"

            except Exception as e:
                logger.error(f"Gateway error while scanning {filename}: {e}", exc_info=True)
                return "451 Security service unavailable"

        logger.info("Email passed inspection and will be delivered")
        return "250 OK"

def run_smtp():
    controller = Controller(
        RansomwareGateway(),
        hostname="0.0.0.0",
        port=Config.GATEWAY_PORT
    )
    controller.start()
    logger.info(f"SMTP Gateway listening on port {Config.GATEWAY_PORT}")
    asyncio.get_event_loop().run_forever()

# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == "__main__":
    logger.info("=== RansomGuard Unified Shield Starting ===")

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    run_smtp()
