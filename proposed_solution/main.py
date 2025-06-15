from .api import start_api
from .fraud_profile import FraudProfile
from .anomaly_detector import AnomalyDetector
import json
import os


def main():
    # Create necessary directories
    os.makedirs("profiles", exist_ok=True)

    # Start the API server
    start_api()


if __name__ == "__main__":
    main()
