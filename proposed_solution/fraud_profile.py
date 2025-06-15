from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import json


@dataclass
class LoginMetrics:
    total_logins: int = 0
    unique_devices: int = 0
    unique_ips: int = 0
    unique_locations: int = 0
    avg_login_interval: float = 0.0
    last_login_time: Optional[datetime] = None
    login_velocity_24h: int = 0
    login_velocity_7d: int = 0
    suspicious_login_count: int = 0


@dataclass
class TransactionMetrics:
    total_transactions: int = 0
    total_amount: float = 0.0
    avg_amount: float = 0.0
    max_amount: float = 0.0
    unique_merchants: int = 0
    transaction_velocity_24h: int = 0
    transaction_velocity_7d: int = 0
    suspicious_transaction_count: int = 0


@dataclass
class SessionMetrics:
    total_sessions: int = 0
    avg_session_duration: float = 0.0
    max_session_duration: float = 0.0
    session_velocity_24h: int = 0
    session_velocity_7d: int = 0


@dataclass
class FeatureUsageMetrics:
    unique_features_used: int = 0
    feature_usage_count: int = 0
    total_frequency: float = 0.0
    avg_feature_frequency: float = 0.0
    std_feature_frequency: float = 0.0
    feature_usage_velocity_24h: int = 0
    feature_usage_velocity_7d: int = 0


@dataclass
class RiskScores:
    login_risk: float = 0.0
    transaction_risk: float = 0.0
    session_risk: float = 0.0
    feature_usage_risk: float = 0.0
    overall_risk: float = 0.0


class FraudProfile:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.login_metrics = LoginMetrics()
        self.transaction_metrics = TransactionMetrics()
        self.session_metrics = SessionMetrics()
        self.feature_usage_metrics = FeatureUsageMetrics()
        self.risk_scores = RiskScores()
        self.last_updated = datetime.now()
        self.historical_changes: List[Dict] = []
        self._initialize_metrics()

    def _initialize_metrics(self):
        """Initialize metrics from historical data if available"""
        try:
            with open(f"profiles/{self.user_id}.json", "r") as f:
                data = json.load(f)
                self._load_from_dict(data)
        except FileNotFoundError:
            pass

    def _load_from_dict(self, data: Dict):
        """Load profile data from dictionary"""
        self.login_metrics = LoginMetrics(**data.get("login_metrics", {}))
        self.transaction_metrics = TransactionMetrics(
            **data.get("transaction_metrics", {})
        )
        self.session_metrics = SessionMetrics(**data.get("session_metrics", {}))
        self.feature_usage_metrics = FeatureUsageMetrics(
            **data.get("feature_usage_metrics", {})
        )
        self.risk_scores = RiskScores(**data.get("risk_scores", {}))
        last_updated = data.get("last_updated")
        self.last_updated = (
            datetime.fromisoformat(last_updated)
            if isinstance(last_updated, str)
            else datetime.now()
        )
        self.historical_changes = data.get("historical_changes", [])

    def update_with_login(self, login_event: Dict):
        """Update profile with new login event"""
        current_time = datetime.fromisoformat(login_event["timestamp"])

        # Update basic metrics
        self.login_metrics.total_logins += 1
        self.login_metrics.unique_devices = len(set([login_event["device_type"]]))
        self.login_metrics.unique_ips = len(set([login_event["ip_address"]]))
        self.login_metrics.unique_locations = len(set([login_event["geolocation"]]))

        # Calculate login interval
        if self.login_metrics.last_login_time:
            interval = (
                current_time - self.login_metrics.last_login_time
            ).total_seconds()
            self.login_metrics.avg_login_interval = (
                self.login_metrics.avg_login_interval
                * (self.login_metrics.total_logins - 1)
                + interval
            ) / self.login_metrics.total_logins

        self.login_metrics.last_login_time = current_time

        # Update velocity metrics
        self._update_velocity_metrics("login", current_time)

        # Record change
        self._record_change("login", login_event)
        self._update_risk_scores()
        self._save_profile()

    def update_with_transaction(self, transaction_event: Dict):
        """Update profile with new transaction event"""
        current_time = datetime.fromisoformat(transaction_event["timestamp"])
        amount = float(transaction_event["amount"])

        # Update basic metrics
        self.transaction_metrics.total_transactions += 1
        self.transaction_metrics.total_amount += amount
        self.transaction_metrics.avg_amount = (
            self.transaction_metrics.total_amount
            / self.transaction_metrics.total_transactions
        )
        self.transaction_metrics.max_amount = max(
            self.transaction_metrics.max_amount, amount
        )
        self.transaction_metrics.unique_merchants = len(
            set([transaction_event["merchant_id"]])
        )

        # Update velocity metrics
        self._update_velocity_metrics("transaction", current_time)

        # Record change
        self._record_change("transaction", transaction_event)
        self._update_risk_scores()
        self._save_profile()

    def update_with_session(self, session_event: Dict):
        """Update profile with new session event"""
        current_time = datetime.fromisoformat(session_event["start_time"])
        duration = float(session_event["session_duration"])

        # Update basic metrics
        self.session_metrics.total_sessions += 1
        self.session_metrics.avg_session_duration = (
            self.session_metrics.avg_session_duration
            * (self.session_metrics.total_sessions - 1)
            + duration
        ) / self.session_metrics.total_sessions
        self.session_metrics.max_session_duration = max(
            self.session_metrics.max_session_duration, duration
        )

        # Update velocity metrics
        self._update_velocity_metrics("session", current_time)

        # Record change
        self._record_change("session", session_event)
        self._update_risk_scores()
        self._save_profile()

    def update_with_feature_usage(self, feature_event: Dict):
        """Update profile with new feature usage event"""
        current_time = datetime.fromisoformat(feature_event["timestamp"])
        frequency = float(feature_event.get("frequency", 1.0))

        # Update basic metrics
        self.feature_usage_metrics.feature_usage_count += 1
        self.feature_usage_metrics.total_frequency += frequency
        self.feature_usage_metrics.avg_feature_frequency = (
            self.feature_usage_metrics.total_frequency
            / self.feature_usage_metrics.feature_usage_count
        )

        # Calculate standard deviation of frequency
        freq_values = [change["event_data"].get("frequency", 1.0)
                      for change in self.historical_changes
                      if change["event_type"] == "feature_usage"]
        freq_values.append(frequency)
        self.feature_usage_metrics.std_feature_frequency = float(np.std(freq_values)) if len(freq_values) > 1 else 0.0

        # Update velocity metrics
        self._update_velocity_metrics("feature_usage", current_time)

        # Record change
        self._record_change("feature_usage", feature_event)
        self._update_risk_scores()
        self._save_profile()

    def _update_velocity_metrics(self, metric_type: str, current_time: datetime):
        """Update velocity metrics for the last 24h and 7d"""
        if metric_type == "login":
            self.login_metrics.login_velocity_24h = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "login"
                    and (
                        current_time - datetime.fromisoformat(change["timestamp"])
                    ).total_seconds()
                    <= 86400
                ]
            )
            self.login_metrics.login_velocity_7d = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "login"
                    and (
                        current_time - datetime.fromisoformat(change["timestamp"])
                    ).total_seconds()
                    <= 604800
                ]
            )
        elif metric_type == "transaction":
            self.transaction_metrics.transaction_velocity_24h = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "transaction"
                    and (
                        current_time - datetime.fromisoformat(change["timestamp"])
                    ).total_seconds()
                    <= 86400
                ]
            )
            self.transaction_metrics.transaction_velocity_7d = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "transaction"
                    and (
                        current_time - datetime.fromisoformat(change["timestamp"])
                    ).total_seconds()
                    <= 604800
                ]
            )
        elif metric_type == "session":
            self.session_metrics.session_velocity_24h = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "session"
                    and (
                        current_time - datetime.fromisoformat(change["start_time"])
                    ).total_seconds()
                    <= 86400
                ]
            )
            self.session_metrics.session_velocity_7d = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "session"
                    and (
                        current_time - datetime.fromisoformat(change["start_time"])
                    ).total_seconds()
                    <= 604800
                ]
            )
        elif metric_type == "feature_usage":
            self.feature_usage_metrics.feature_usage_velocity_24h = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "feature_usage"
                    and (
                        current_time - datetime.fromisoformat(change["timestamp"])
                    ).total_seconds()
                    <= 86400
                ]
            )
            self.feature_usage_metrics.feature_usage_velocity_7d = len(
                [
                    change
                    for change in self.historical_changes
                    if change["event_type"] == "feature_usage"
                    and (
                        current_time - datetime.fromisoformat(change["timestamp"])
                    ).total_seconds()
                    <= 604800
                ]
            )

    def _update_risk_scores(self):
        """Update risk scores based on current metrics"""
        # Login risk score (0-1)
        self.risk_scores.login_risk = min(
            1.0,
            (
                (self.login_metrics.login_velocity_24h / 10) * 0.3
                + (self.login_metrics.unique_locations / 5) * 0.3
                + (self.login_metrics.unique_devices / 3) * 0.4
            ),
        )

        # Transaction risk score (0-1)
        self.risk_scores.transaction_risk = min(
            1.0,
            (
                (self.transaction_metrics.transaction_velocity_24h / 20) * 0.3
                + (self.transaction_metrics.avg_amount / 1000) * 0.4
                + (self.transaction_metrics.unique_merchants / 10) * 0.3
            ),
        )

        # Session risk score (0-1)
        self.risk_scores.session_risk = min(
            1.0,
            (
                (self.session_metrics.session_velocity_24h / 15) * 0.4
                + (self.session_metrics.avg_session_duration / 3600) * 0.6
            ),
        )

        # Feature usage risk score (0-1)
        self.risk_scores.feature_usage_risk = min(
            1.0,
            (
                (self.feature_usage_metrics.feature_usage_velocity_24h / 50) * 0.3
                + (self.feature_usage_metrics.std_feature_frequency) * 0.4
                + (self.feature_usage_metrics.avg_feature_frequency / 10) * 0.3
            ),
        )

        # Overall risk score (0-1)
        self.risk_scores.overall_risk = (
            self.risk_scores.login_risk * 0.3
            + self.risk_scores.transaction_risk * 0.3
            + self.risk_scores.session_risk * 0.2
            + self.risk_scores.feature_usage_risk * 0.2
        )

    def _record_change(self, event_type: str, event_data: Dict):
        """Record historical changes to profile"""
        self.historical_changes.append(
            {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "event_data": event_data,
            }
        )
        self.last_updated = datetime.now()

    def _save_profile(self):
        """Save profile to disk"""
        import os

        os.makedirs("profiles", exist_ok=True)

        profile_data = {
            "login_metrics": self.login_metrics.__dict__,
            "transaction_metrics": self.transaction_metrics.__dict__,
            "session_metrics": self.session_metrics.__dict__,
            "feature_usage_metrics": self.feature_usage_metrics.__dict__,
            "risk_scores": self.risk_scores.__dict__,
            "last_updated": self.last_updated.isoformat(),
            "historical_changes": self.historical_changes,
        }

        with open(f"profiles/{self.user_id}.json", "w") as f:
            json.dump(profile_data, f, indent=2)

    def to_dict(self) -> Dict:
        """Convert profile to dictionary"""
        return {
            "user_id": self.user_id,
            "login_metrics": self.login_metrics.__dict__,
            "transaction_metrics": self.transaction_metrics.__dict__,
            "session_metrics": self.session_metrics.__dict__,
            "feature_usage_metrics": self.feature_usage_metrics.__dict__,
            "risk_scores": self.risk_scores.__dict__,
            "last_updated": self.last_updated.isoformat(),
            "historical_changes": self.historical_changes,
        }


def create_user_features(
    logins_df: pd.DataFrame,
    sessions_df: pd.DataFrame,
    transactions_df: pd.DataFrame,
    feature_usage_df: pd.DataFrame,
) -> Dict[str, FraudProfile]:
    """
    Create fraud profiles for all users from historical data.

    Args:
        logins_df: DataFrame containing login events
        sessions_df: DataFrame containing session events
        transactions_df: DataFrame containing transaction events
        feature_usage_df: DataFrame containing feature usage events

    Returns:
        Dict mapping user_ids to their FraudProfile objects
    """
    # Convert timestamps to datetime
    logins_df["timestamp"] = pd.to_datetime(logins_df["timestamp"])
    sessions_df["start_time"] = pd.to_datetime(sessions_df["start_time"])
    transactions_df["timestamp"] = pd.to_datetime(transactions_df["timestamp"])
    feature_usage_df["timestamp"] = pd.to_datetime(feature_usage_df["timestamp"])

    # Initialize profiles dictionary
    profiles = {}

    # Process each user
    for user_id in logins_df["user_id"].unique():
        profile = FraudProfile(user_id)

        # Process login events
        user_logins = logins_df[logins_df["user_id"] == user_id].sort_values(
            "timestamp"
        )
        for _, login in user_logins.iterrows():
            login_dict = login.to_dict()
            if isinstance(login_dict["timestamp"], str):
                profile.update_with_login(login_dict)

        # Process session events
        user_sessions = sessions_df[sessions_df["user_id"] == user_id].sort_values(
            "start_time"
        )
        for _, session in user_sessions.iterrows():
            session_dict = session.to_dict()
            if isinstance(session_dict["start_time"], str):
                profile.update_with_session(session_dict)

        # Process transaction events
        user_transactions = transactions_df[
            transactions_df["user_id"] == user_id
        ].sort_values("timestamp")
        for _, transaction in user_transactions.iterrows():
            transaction_dict = transaction.to_dict()
            if isinstance(transaction_dict["timestamp"], str):
                profile.update_with_transaction(transaction_dict)

        # Process feature usage events
        user_features = feature_usage_df[
            feature_usage_df["user_id"] == user_id
        ].sort_values("timestamp")
        for _, feature in user_features.iterrows():
            feature_dict = feature.to_dict()
            if isinstance(feature_dict["timestamp"], str):
                profile.update_with_feature_usage(feature_dict)

        # Store profile
        profiles[user_id] = profile

    return profiles
