"""Queen Califia CyberAI — QC OS v4.2 (merged definitive)"""
from __future__ import annotations
import os
from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from core.settings import get_settings, parse_origins
from core.database import init_db

load_dotenv()

def create_app() -> Flask:
    settings = get_settings()
    init_db(settings.db_path)
    app = Flask(__name__)
    app.config["settings"] = settings
    CORS(app, resources={r"/api/*": {"origins": parse_origins(settings.cors_origins)}}, supports_credentials=False)

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True, "service": settings.name, "version": "4.2.0"})

    @app.get("/api/config")
    def api_config():
        return jsonify({
            "name": settings.name, "persona": settings.persona,
            "modes": ["cyber", "research", "lab"],
            "capabilities": ["conversation", "memory", "telemetry", "market_snapshot",
                             "portfolio_analysis", "forecast", "admin_quant_mode"],
            "welcome_message": f"I am {settings.name}. Tell me who you are, what you want to build, "
                               "or which market, system, or portfolio you want to understand.",
        })

    from modules.conversation.routes import conversation_bp
    from modules.market.routes import market_bp
    from modules.forecast.routes import forecast_bp
    from modules.identity.routes import identity_bp
    app.register_blueprint(conversation_bp, url_prefix="/api/chat")
    app.register_blueprint(market_bp, url_prefix="/api/market")
    app.register_blueprint(forecast_bp, url_prefix="/api/forecast")
    app.register_blueprint(identity_bp, url_prefix="/api/identity")
    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
