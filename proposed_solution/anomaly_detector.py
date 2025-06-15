import os
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import pandas as pd
from .fraud_profile import FraudProfile


class AnomalyDetector:
    def __init__(self):
        self.models = {
            "login": IsolationForest(contamination=0.1, random_state=42),
            "transaction": LocalOutlierFactor(n_neighbors=20, contamination=0.1),
            "session": IsolationForest(contamination=0.1, random_state=42),
            "feature_usage": IsolationForest(contamination=0.1, random_state=42),
        }
        self.scalers = {
            "login": StandardScaler(),
            "transaction": StandardScaler(),
            "session": StandardScaler(),
            "feature_usage": StandardScaler(),
        }
        self._initialize_models()

    def _initialize_models(self):
        """Initialize models with historical data if available"""
        try:

            # Load all profile data
            profiles_dir = "profiles"
            if not os.path.exists(profiles_dir):
                return

            all_features = {
                "login": [],
                "transaction": [],
                "session": [],
                "feature_usage": [],
            }

            # Collect features from all profiles
            for filename in os.listdir(profiles_dir):
                if filename.endswith(".json"):
                    with open(os.path.join(profiles_dir, filename), "r") as f:
                        profile_data = json.load(f)

                        # Extract login features
                        login_metrics = profile_data.get("login_metrics", {})
                        all_features["login"].append(
                            [
                                login_metrics.get("login_velocity_24h", 0),
                                login_metrics.get("unique_locations", 0),
                                login_metrics.get("unique_devices", 0),
                                login_metrics.get("avg_login_interval", 0),
                            ]
                        )

                        # Extract transaction features
                        transaction_metrics = profile_data.get(
                            "transaction_metrics", {}
                        )
                        all_features["transaction"].append(
                            [
                                transaction_metrics.get("transaction_velocity_24h", 0),
                                transaction_metrics.get("avg_amount", 0),
                                transaction_metrics.get("max_amount", 0),
                                transaction_metrics.get("unique_merchants", 0),
                            ]
                        )

                        # Extract session features
                        session_metrics = profile_data.get("session_metrics", {})
                        all_features["session"].append(
                            [
                                session_metrics.get("session_velocity_24h", 0),
                                session_metrics.get("avg_session_duration", 0),
                                session_metrics.get("max_session_duration", 0),
                                session_metrics.get("total_sessions", 0),
                            ]
                        )

                        # Extract feature usage features
                        feature_usage_metrics = profile_data.get("feature_usage_metrics", {})
                        all_features["feature_usage"].append(
                            [
                                feature_usage_metrics.get("feature_usage_velocity_24h", 0),
                                feature_usage_metrics.get("unique_features_used", 0),
                                feature_usage_metrics.get("avg_feature_frequency", 0),
                                feature_usage_metrics.get("std_feature_frequency", 0),
                                feature_usage_metrics.get("total_frequency", 0),
                            ]
                        )

            # Fit scalers and models for each event type
            for event_type in ["login", "transaction", "session", "feature_usage"]:
                if all_features[event_type]:
                    features_array = np.array(all_features[event_type])
                    self.scalers[event_type].fit(features_array)
                    scaled_features = self.scalers[event_type].transform(features_array)
                    self.models[event_type].fit(scaled_features)

        except Exception as e:
            print(f"Error initializing models: {str(e)}")
            pass

    def detect_anomaly(
        self, profile: FraudProfile, event_type: str, event_data: Dict
    ) -> Tuple[bool, float, Dict]:
        """
        Detect anomalies in new events
        Returns: (is_anomaly, confidence_score, explanation)
        """
        features = self._extract_features(profile, event_type, event_data)
        scaled_features = self.scalers[event_type].transform(np.array([features]))

        if event_type == "login":
            score = self.models[event_type].score_samples(scaled_features)[0]
            is_anomaly = score < np.percentile(
                self.models[event_type].score_samples(scaled_features), 10
            )
        else:
            score = -self.models[event_type].score_samples(scaled_features)[0]
            is_anomaly = score > np.percentile(
                -self.models[event_type].score_samples(scaled_features), 90
            )

        explanation = self._generate_explanation(
            profile, event_type, event_data, features, score
        )

        return is_anomaly, abs(score), explanation

    def _extract_features(
        self, profile: FraudProfile, event_type: str, event_data: Dict
    ) -> List[float]:
        """Extract relevant features for anomaly detection"""
        if event_type == "login":
            return [
                profile.login_metrics.login_velocity_24h,
                profile.login_metrics.unique_locations,
                profile.login_metrics.unique_devices,
                profile.login_metrics.avg_login_interval,
            ]
        elif event_type == "transaction":
            return [
                profile.transaction_metrics.transaction_velocity_24h,
                float(event_data["amount"]),
                profile.transaction_metrics.avg_amount,
                profile.transaction_metrics.unique_merchants,
            ]
        elif event_type == "feature_usage":
            return [
                profile.feature_usage_metrics.feature_usage_velocity_24h,
                profile.feature_usage_metrics.unique_features_used,
                profile.feature_usage_metrics.avg_feature_frequency,
                profile.feature_usage_metrics.std_feature_frequency,
                profile.feature_usage_metrics.total_frequency,
            ]
        else:  # session
            return [
                profile.session_metrics.session_velocity_24h,
                float(event_data["session_duration"]),
                profile.session_metrics.avg_session_duration,
                profile.session_metrics.total_sessions,
            ]

    def _generate_explanation(
        self,
        profile: FraudProfile,
        event_type: str,
        event_data: Dict,
        features: List[float],
        score: float,
    ) -> Dict:
        """Generate explanation for anomaly detection result"""
        if event_type == "login":
            return {
                "velocity_24h": features[0],
                "unique_locations": features[1],
                "unique_devices": features[2],
                "avg_interval": features[3],
                "anomaly_score": score,
                "risk_factors": [
                    "High login velocity" if features[0] > 10 else None,
                    "Multiple locations" if features[1] > 3 else None,
                    "Multiple devices" if features[2] > 2 else None,
                ],
            }
        elif event_type == "transaction":
            return {
                "velocity_24h": features[0],
                "amount": features[1],
                "avg_amount": features[2],
                "unique_merchants": features[3],
                "anomaly_score": score,
                "risk_factors": [
                    "High transaction velocity" if features[0] > 20 else None,
                    "Large amount" if features[1] > features[2] * 2 else None,
                    "Unusual merchant" if features[3] > 5 else None,
                ],
            }
        elif event_type == "feature_usage":
            return {
                "velocity_24h": features[0],
                "unique_features": features[1],
                "avg_frequency": features[2],
                "std_frequency": features[3],
                "total_frequency": features[4],
                "anomaly_score": score,
                "risk_factors": [
                    "High feature usage velocity" if features[0] > 50 else None,
                    "Unusual number of features" if features[1] > 10 else None,
                    "Abnormal usage frequency" if features[3] > features[2] else None,
                    "High total frequency" if features[4] > 100 else None,
                ],
            }
        else:  # session
            return {
                "velocity_24h": features[0],
                "duration": features[1],
                "avg_duration": features[2],
                "total_sessions": features[3],
                "anomaly_score": score,
                "risk_factors": [
                    "High session velocity" if features[0] > 15 else None,
                    "Long duration" if features[1] > 3600 else None,
                    "Multiple sessions" if features[3] > 10 else None,
                ],
            }
