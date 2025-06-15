from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class LoginMetadata(BaseModel):
    user_id: str
    timestamp: datetime
    device_type: str
    os_browser: str
    screen_resolution: str
    ip_address: str
    geolocation: str
    login_method: str
    channel: str


class SessionMetadata(BaseModel):
    user_id: str
    session_id: str
    start_time: datetime
    end_time: datetime
    pages_visited: List[str]
    session_duration: float  # in seconds


class TransactionMetadata(BaseModel):
    user_id: str
    transaction_id: str
    transaction_type: str
    amount: float
    recipient: str
    method: str
    timestamp: datetime


class FeatureUsage(BaseModel):
    user_id: str
    feature_name: str
    timestamp: datetime
    frequency: int = 1


class FraudProfile(BaseModel):
    user_id: str
    last_updated: datetime
    login_patterns: dict = Field(default_factory=dict)
    device_patterns: dict = Field(default_factory=dict)
    session_patterns: dict = Field(default_factory=dict)
    transaction_patterns: dict = Field(default_factory=dict)
    feature_usage_patterns: dict = Field(default_factory=dict)
    risk_score: float = 0.0
