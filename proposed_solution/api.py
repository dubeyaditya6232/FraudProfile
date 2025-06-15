from fastapi import FastAPI, HTTPException
from typing import Dict, List
import uvicorn
from .fraud_profile import FraudProfile
from .anomaly_detector import AnomalyDetector

app = FastAPI(title="Fraud Profile API")
anomaly_detector = AnomalyDetector()


@app.get("/profile/{user_id}")
async def get_profile(user_id: str) -> Dict:
    """Get user's fraud profile"""
    try:
        profile = FraudProfile(user_id)
        return profile.to_dict()
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/profile/{user_id}/login")
async def process_login(user_id: str, login_event: Dict) -> Dict:
    """Process new login event"""
    try:
        profile = FraudProfile(user_id)
        is_anomaly, confidence, explanation = anomaly_detector.detect_anomaly(
            profile, "login", login_event
        )

        if is_anomaly:
            profile.login_metrics.suspicious_login_count += 1

        profile.update_with_login(login_event)

        return {
            "profile": profile.to_dict(),
            "anomaly_detection": {
                "is_anomaly": is_anomaly,
                "confidence": confidence,
                "explanation": explanation,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/profile/{user_id}/transaction")
async def process_transaction(user_id: str, transaction_event: Dict) -> Dict:
    """Process new transaction event"""
    try:
        profile = FraudProfile(user_id)
        is_anomaly, confidence, explanation = anomaly_detector.detect_anomaly(
            profile, "transaction", transaction_event
        )

        if is_anomaly:
            profile.transaction_metrics.suspicious_transaction_count += 1

        profile.update_with_transaction(transaction_event)

        return {
            "profile": profile.to_dict(),
            "anomaly_detection": {
                "is_anomaly": is_anomaly,
                "confidence": confidence,
                "explanation": explanation,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/profile/{user_id}/session")
async def process_session(user_id: str, session_event: Dict) -> Dict:
    """Process new session event"""
    try:
        profile = FraudProfile(user_id)
        profile.update_with_session(session_event)

        return {"profile": profile.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/profile/{user_id}/feature")
async def process_feature_usage(user_id: str, feature_event: Dict) -> Dict:
    """Process new feature usage event"""
    try:
        profile = FraudProfile(user_id)
        is_anomaly, confidence, explanation = anomaly_detector.detect_anomaly(
            profile, "feature_usage", feature_event
        )

        profile.update_with_feature_usage(feature_event)

        return {
            "profile": profile.to_dict(),
            "anomaly_detection": {
                "is_anomaly": is_anomaly,
                "confidence": confidence,
                "explanation": explanation,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/profile/{user_id}/risk")
async def get_risk_assessment(user_id: str) -> Dict:
    """Get risk assessment for user"""
    try:
        profile = FraudProfile(user_id)
        return {
            "user_id": user_id,
            "risk_scores": profile.risk_scores.__dict__,
            "suspicious_activities": {
                "login_count": profile.login_metrics.suspicious_login_count,
                "transaction_count": profile.transaction_metrics.suspicious_transaction_count,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


def start_api():
    """Start the API server"""
    uvicorn.run(app, host="0.0.0.0", port=8000)
