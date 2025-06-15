# Dynamic Fraud Profile Engine

A Python-based system for generating and maintaining dynamic fraud profiles for internet banking users. This system processes historical login, navigation, and transaction logs to construct per-user fraud profiles that can be used for anomaly detection.

## Features

- Synthetic data generation for testing and development
- Comprehensive user behavior profiling
- Real-time risk scoring
- Pattern analysis for:
  - Login behavior
  - Device usage
  - Transaction patterns
  - Feature usage
  - Session characteristics

## Project Structure

- `models.py`: Data models and schemas
- `data_generator.py`: Synthetic data generation
- `fraud_profile_engine.py`: Core fraud profile processing engine
- `main.py`: Example usage and demonstration

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the example script:
```bash
python main.py
```

This will:
1. Generate synthetic user data
2. Process the data to create fraud profiles
3. Display a sample profile summary

## Data Models

### Login Metadata
- User ID
- Timestamp
- Device type
- OS/Browser
- Screen resolution
- IP/Geolocation
- Login method
- Channel

### Session Metadata
- Session duration
- Pages/screens visited
- Start/End times

### Transaction Metadata
- Transaction type
- Amount
- Recipient
- Method
- Timestamp

### Feature Usage
- Feature name
- Frequency
- Timestamps

## Risk Scoring

The system calculates a risk score (0-1) based on:
- Unusual login patterns
- Transaction amount variations
- Session duration anomalies
- Device usage patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License 