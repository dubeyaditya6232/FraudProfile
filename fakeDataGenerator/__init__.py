# This file makes the directory a Python package

"""
FakeDataGenerator - A package for generating synthetic banking data and fraud profiles.
"""

# Define which modules can be imported when using 'from fakeDataGenerator import *'
__all__ = ["data_generator", "fraud_profile_engine"]

# Import key classes and functions to make them available at package level
from .data_generator import BankingDataGenerator
from .fraud_profile_engine import FraudProfileEngine

# Version information
__version__ = "1.0.0"
