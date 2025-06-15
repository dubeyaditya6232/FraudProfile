import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List
import pandas as pd
from datetime import datetime, timedelta
from .fraud_profile import FraudProfile


def create_profile_dashboard(profile: FraudProfile) -> Dict:
    """Create interactive dashboard for profile visualization"""
    # Create risk score gauge
    risk_gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=profile.risk_scores.overall_risk * 100,
            title={"text": "Overall Risk Score"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "darkblue"},
                "steps": [
                    {"range": [0, 30], "color": "lightgray"},
                    {"range": [30, 70], "color": "gray"},
                    {"range": [70, 100], "color": "darkgray"},
                ],
            },
        )
    )

    # Create historical activity plot
    historical_data = pd.DataFrame(profile.historical_changes)
    historical_data["timestamp"] = pd.to_datetime(historical_data["timestamp"])

    activity_plot = px.scatter(
        historical_data,
        x="timestamp",
        y="event_type",
        color="event_type",
        title="Historical Activity",
    )

    # Create metrics summary
    metrics_summary = {
        "login_metrics": {
            "total_logins": profile.login_metrics.total_logins,
            "unique_devices": profile.login_metrics.unique_devices,
            "suspicious_logins": profile.login_metrics.suspicious_login_count,
        },
        "transaction_metrics": {
            "total_transactions": profile.transaction_metrics.total_transactions,
            "total_amount": profile.transaction_metrics.total_amount,
            "avg_amount": profile.transaction_metrics.avg_amount,
        },
        "session_metrics": {
            "total_sessions": profile.session_metrics.total_sessions,
            "avg_duration": profile.session_metrics.avg_session_duration,
        },
        "feature_usage_metrics": {
            "unique_features": profile.feature_usage_metrics.unique_features_used,
            "usage_count": profile.feature_usage_metrics.feature_usage_count,
            "avg_frequency": profile.feature_usage_metrics.avg_feature_frequency,
            "std_frequency": profile.feature_usage_metrics.std_feature_frequency,
        },
    }

    return {
        "risk_gauge": risk_gauge.to_json(),
        "activity_plot": activity_plot.to_json(),
        "metrics_summary": metrics_summary,
    }


def create_anomaly_visualization(anomaly_results: Dict) -> Dict:
    """Create visualization for anomaly detection results"""
    # Create anomaly score bar chart
    scores = {
        "login": anomaly_results["login"]["score"],
        "transaction": anomaly_results["transaction"]["score"],
        "session": anomaly_results["session"]["score"],
    }

    score_chart = px.bar(
        x=list(scores.keys()),
        y=list(scores.values()),
        title="Anomaly Scores by Event Type",
    )

    # Create risk factors summary
    risk_factors = {
        "login": anomaly_results["login"]["explanation"]["risk_factors"],
        "transaction": anomaly_results["transaction"]["explanation"]["risk_factors"],
        "session": anomaly_results["session"]["explanation"]["risk_factors"],
    }

    return {"score_chart": score_chart.to_json(), "risk_factors": risk_factors}
