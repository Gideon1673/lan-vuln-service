import os
import logging

from flask import Flask, jsonify

from app.common.database import db
from app.cve_matching.repository import get_findings

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.get("/health")
def health():
    try:
        db.ping()
        return jsonify({
            "service": "vulnerability-service",
            "status": "UP",
            "database": "UP"
        })

    except Exception:
        logger.exception("Database health check failed")
        return jsonify({
            "service": "vulnerability-service",
            "status": "DOWN",
            "database": "DOWN"
        }), 503


@app.get("/api/v1/findings/<scan_id>")
def findings(scan_id):
    try:
        results = get_findings(scan_id)
        return jsonify({
            "scan_id": scan_id,
            "total": len(results),
            "findings": results
        })

    except Exception:
        logger.exception("Failed to load findings: scan=%s", scan_id)
        return jsonify({
            "error": "DATABASE_ERROR",
            "message": "Cannot load findings"
        }), 500


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "8082"))
    )
