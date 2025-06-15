"""
Data generator module for creating synthetic banking data.
"""

import random
from datetime import datetime, timedelta
from typing import List, Dict
from faker import Faker
from .models import LoginMetadata, SessionMetadata, TransactionMetadata, FeatureUsage


class BankingDataGenerator:
    def __init__(self, num_users: int = 1000):
        self.faker = Faker()
        self.num_users = num_users
        self.user_ids = [f"USER_{i:06d}" for i in range(num_users)]
        self.device_types = ["Mobile", "Desktop", "Tablet"]
        self.os_browsers = [
            "Windows/Chrome",
            "Windows/Firefox",
            "Mac/Safari",
            "iOS/Safari",
            "Android/Chrome",
        ]
        self.screen_resolutions = [
            "1920x1080",
            "1366x768",
            "1440x900",
            "375x812",
            "414x896",
        ]
        self.login_methods = ["Password", "2FA", "Biometric"]
        self.channels = ["Web", "Mobile App", "Tablet App"]
        self.transaction_types = ["Transfer", "Bill Payment", "Card Payment"]
        self.payment_methods = ["ACH", "Wire", "Card", "Zelle"]
        self.features = [
            "Account Balance",
            "Transfer Money",
            "Bill Pay",
            "Card Management",
            "Statement Download",
        ]

    def generate_login_data(self, num_records: int) -> List[LoginMetadata]:
        logins = []
        for _ in range(num_records):
            user_id = random.choice(self.user_ids)
            timestamp = self.faker.date_time_between(start_date="-30d", end_date="now")
            login = LoginMetadata(
                user_id=user_id,
                timestamp=timestamp,
                device_type=random.choice(self.device_types),
                os_browser=random.choice(self.os_browsers),
                screen_resolution=random.choice(self.screen_resolutions),
                ip_address=self.faker.ipv4(),
                geolocation=f"{self.faker.latitude()},{self.faker.longitude()}",
                login_method=random.choice(self.login_methods),
                channel=random.choice(self.channels),
            )
            logins.append(login)
        return logins

    def generate_session_data(self, num_records: int) -> List[SessionMetadata]:
        sessions = []
        for _ in range(num_records):
            user_id = random.choice(self.user_ids)
            start_time = self.faker.date_time_between(start_date="-30d", end_date="now")
            duration = random.randint(300, 3600)  # 5 minutes to 1 hour
            end_time = start_time + timedelta(seconds=duration)

            # Generate random pages visited (ensure we don't try to sample more than available)
            num_pages = min(random.randint(3, 10), len(self.features))
            pages = random.sample(self.features, num_pages)

            session = SessionMetadata(
                user_id=user_id,
                session_id=f"SESS_{self.faker.uuid4()}",
                start_time=start_time,
                end_time=end_time,
                pages_visited=pages,
                session_duration=duration,
            )
            sessions.append(session)
        return sessions

    def generate_transaction_data(self, num_records: int) -> List[TransactionMetadata]:
        transactions = []
        for _ in range(num_records):
            user_id = random.choice(self.user_ids)
            transaction = TransactionMetadata(
                user_id=user_id,
                transaction_id=f"TXN_{self.faker.uuid4()}",
                transaction_type=random.choice(self.transaction_types),
                amount=round(random.uniform(10.0, 10000.0), 2),
                recipient=self.faker.name(),
                method=random.choice(self.payment_methods),
                timestamp=self.faker.date_time_between(
                    start_date="-30d", end_date="now"
                ),
            )
            transactions.append(transaction)
        return transactions

    def generate_feature_usage_data(self, num_records: int) -> List[FeatureUsage]:
        feature_usage = []
        for _ in range(num_records):
            user_id = random.choice(self.user_ids)
            usage = FeatureUsage(
                user_id=user_id,
                feature_name=random.choice(self.features),
                timestamp=self.faker.date_time_between(
                    start_date="-30d", end_date="now"
                ),
                frequency=random.randint(1, 5),
            )
            feature_usage.append(usage)
        return feature_usage
