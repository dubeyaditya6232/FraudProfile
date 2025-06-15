from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any
import numpy as np
from .models import (
    LoginMetadata,
    SessionMetadata,
    TransactionMetadata,
    FeatureUsage,
    FraudProfile,
)


class FraudProfileEngine:
    def __init__(self):
        self.profiles: Dict[str, FraudProfile] = {}

    def _calculate_login_patterns(self, logins: List[LoginMetadata]) -> Dict[str, Any]:
        patterns = {
            "device_frequency": defaultdict(int),
            "os_browser_frequency": defaultdict(int),
            "login_method_frequency": defaultdict(int),
            "channel_frequency": defaultdict(int),
            "ip_frequency": defaultdict(int),
            "geolocation_frequency": defaultdict(int),
            "login_times": [],
        }

        for login in logins:
            patterns["device_frequency"][login.device_type] += 1
            patterns["os_browser_frequency"][login.os_browser] += 1
            patterns["login_method_frequency"][login.login_method] += 1
            patterns["channel_frequency"][login.channel] += 1
            patterns["ip_frequency"][login.ip_address] += 1
            patterns["geolocation_frequency"][login.geolocation] += 1
            patterns["login_times"].append(login.timestamp.hour)

        # Convert frequencies to percentages
        total_logins = len(logins)
        for key in [
            "device_frequency",
            "os_browser_frequency",
            "login_method_frequency",
            "channel_frequency",
        ]:
            patterns[key] = {k: v / total_logins for k, v in patterns[key].items()}

        # Calculate typical login hours
        patterns["typical_login_hours"] = np.percentile(
            patterns["login_times"], [25, 75]
        )

        return patterns

    def _calculate_session_patterns(
        self, sessions: List[SessionMetadata]
    ) -> Dict[str, Any]:
        patterns = {
            "avg_session_duration": 0,
            "typical_pages": defaultdict(int),
            "session_frequency": defaultdict(int),
        }

        if not sessions:
            return patterns

        # Calculate average session duration
        durations = [s.session_duration for s in sessions]
        patterns["avg_session_duration"] = np.mean(durations)

        # Calculate typical pages visited
        for session in sessions:
            for page in session.pages_visited:
                patterns["typical_pages"][page] += 1

        # Convert page frequencies to percentages
        total_sessions = len(sessions)
        patterns["typical_pages"] = {
            k: v / total_sessions for k, v in patterns["typical_pages"].items()
        }

        # Calculate session frequency by hour
        for session in sessions:
            hour = session.start_time.hour
            patterns["session_frequency"][hour] += 1

        return patterns

    def _calculate_transaction_patterns(
        self, transactions: List[TransactionMetadata]
    ) -> Dict[str, Any]:
        patterns = {
            "transaction_types": defaultdict(int),
            "payment_methods": defaultdict(int),
            "amount_stats": {"mean": 0, "std": 0, "min": 0, "max": 0},
            "transaction_times": [],
        }

        if not transactions:
            return patterns

        # Calculate transaction type and payment method frequencies
        for tx in transactions:
            patterns["transaction_types"][tx.transaction_type] += 1
            patterns["payment_methods"][tx.method] += 1
            patterns["transaction_times"].append(tx.timestamp.hour)

        # Convert frequencies to percentages
        total_tx = len(transactions)
        patterns["transaction_types"] = {
            k: v / total_tx for k, v in patterns["transaction_types"].items()
        }
        patterns["payment_methods"] = {
            k: v / total_tx for k, v in patterns["payment_methods"].items()
        }

        # Calculate amount statistics
        amounts = [tx.amount for tx in transactions]
        patterns["amount_stats"] = {
            "mean": np.mean(amounts),
            "std": np.std(amounts),
            "min": np.min(amounts),
            "max": np.max(amounts),
        }

        # Calculate typical transaction hours
        patterns["typical_transaction_hours"] = np.percentile(
            patterns["transaction_times"], [25, 75]
        )

        return patterns

    def _calculate_feature_usage_patterns(
        self, feature_usage: List[FeatureUsage]
    ) -> Dict[str, Any]:
        patterns = {"feature_frequency": defaultdict(int), "usage_times": []}

        if not feature_usage:
            return patterns

        # Calculate feature usage frequencies
        for usage in feature_usage:
            patterns["feature_frequency"][usage.feature_name] += usage.frequency
            patterns["usage_times"].append(usage.timestamp.hour)

        # Convert frequencies to percentages
        total_usage = sum(patterns["feature_frequency"].values())
        patterns["feature_frequency"] = {
            k: v / total_usage for k, v in patterns["feature_frequency"].items()
        }

        # Calculate typical usage hours
        patterns["typical_usage_hours"] = np.percentile(
            patterns["usage_times"], [25, 75]
        )

        return patterns

    def _calculate_risk_score(self, profile: FraudProfile) -> float:
        # This is a simplified risk scoring mechanism
        # In a real system, this would be more sophisticated
        risk_factors = []

        # Check for unusual login patterns
        if len(profile.login_patterns["ip_frequency"]) > 3:
            risk_factors.append(0.2)

        # Check for unusual transaction amounts
        if profile.transaction_patterns["amount_stats"]["std"] > 1000:
            risk_factors.append(0.3)

        # Check for unusual session durations
        if (
            profile.session_patterns["avg_session_duration"] > 1800
        ):  # More than 30 minutes
            risk_factors.append(0.1)

        # Calculate final risk score (0-1)
        return min(sum(risk_factors), 1.0)

    def update_profile(
        self,
        user_id: str,
        logins: List[LoginMetadata],
        sessions: List[SessionMetadata],
        transactions: List[TransactionMetadata],
        feature_usage: List[FeatureUsage],
    ) -> FraudProfile:

        # Filter data for specific user
        user_logins = [l for l in logins if l.user_id == user_id]
        user_sessions = [s for s in sessions if s.user_id == user_id]
        user_transactions = [t for t in transactions if t.user_id == user_id]
        user_feature_usage = [f for f in feature_usage if f.user_id == user_id]

        # Calculate patterns
        login_patterns = self._calculate_login_patterns(user_logins)
        session_patterns = self._calculate_session_patterns(user_sessions)
        transaction_patterns = self._calculate_transaction_patterns(user_transactions)
        feature_usage_patterns = self._calculate_feature_usage_patterns(
            user_feature_usage
        )

        # Create or update profile
        profile = FraudProfile(
            user_id=user_id,
            last_updated=datetime.now(),
            login_patterns=login_patterns,
            device_patterns=login_patterns,  # Reusing login patterns for device patterns
            session_patterns=session_patterns,
            transaction_patterns=transaction_patterns,
            feature_usage_patterns=feature_usage_patterns,
        )

        # Calculate risk score
        profile.risk_score = self._calculate_risk_score(profile)

        # Store profile
        self.profiles[user_id] = profile
        return profile

    def get_profile(self, user_id: str) -> FraudProfile:
        profile = self.profiles.get(user_id)
        if profile is None:
            raise KeyError(f"Profile not found for user_id: {user_id}")
        return profile
