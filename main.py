from fakeDataGenerator import BankingDataGenerator
from fakeDataGenerator import FraudProfileEngine
import pandas as pd
import os


def flatten_profile(profile):
    # Flatten only the most relevant fields for CSV
    return {
        "user_id": profile.user_id,
        "last_updated": profile.last_updated,
        "risk_score": profile.risk_score,
        # Login patterns
        "most_common_device": (
            max(profile.login_patterns["device_frequency"].items(), key=lambda x: x[1])[
                0
            ]
            if profile.login_patterns["device_frequency"]
            else ""
        ),
        "most_common_login_method": (
            max(
                profile.login_patterns["login_method_frequency"].items(),
                key=lambda x: x[1],
            )[0]
            if profile.login_patterns["login_method_frequency"]
            else ""
        ),
        # Transaction patterns
        "avg_transaction_amount": (
            profile.transaction_patterns["amount_stats"]["mean"]
            if "mean" in profile.transaction_patterns["amount_stats"]
            else 0
        ),
        "most_common_transaction_type": (
            max(
                profile.transaction_patterns["transaction_types"].items(),
                key=lambda x: x[1],
            )[0]
            if profile.transaction_patterns["transaction_types"]
            else ""
        ),
        # Feature usage
        "most_used_feature": (
            max(
                profile.feature_usage_patterns["feature_frequency"].items(),
                key=lambda x: x[1],
            )[0]
            if profile.feature_usage_patterns["feature_frequency"]
            else ""
        ),
    }


def save_to_csv(data, filename):
    # Convert list of objects to list of dictionaries
    data_dicts = [item.model_dump() for item in data]
    # Create DataFrame and save to CSV
    df = pd.DataFrame(data_dicts)
    # Get the project root directory (parent of fakeDataGenerator)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Create dataset directory in project root
    dataset_dir = os.path.join(project_root, "dataset")
    os.makedirs(dataset_dir, exist_ok=True)
    # Save to CSV in dataset directory
    output_path = os.path.join(dataset_dir, filename)
    df.to_csv(output_path, index=False)
    print(f"Saved {len(data)} records to {output_path}")


def main():
    # Initialize the data generator and fraud profile engine
    data_generator = BankingDataGenerator(num_users=100)
    fraud_engine = FraudProfileEngine()

    # Generate synthetic data
    print("Generating synthetic data...")
    logins = data_generator.generate_login_data(1000)
    sessions = data_generator.generate_session_data(500)
    transactions = data_generator.generate_transaction_data(2000)
    feature_usage = data_generator.generate_feature_usage_data(3000)

    # Save raw data to CSV files
    print("\nSaving data to CSV files...")
    save_to_csv(logins, "logins.csv")
    save_to_csv(sessions, "sessions.csv")
    save_to_csv(transactions, "transactions.csv")
    save_to_csv(feature_usage, "feature_usage.csv")

    # Process data for each user
    print("\nProcessing user profiles...")
    all_profiles = []
    for user_id in data_generator.user_ids:
        profile = fraud_engine.update_profile(
            user_id=user_id,
            logins=logins,
            sessions=sessions,
            transactions=transactions,
            feature_usage=feature_usage,
        )
        all_profiles.append(flatten_profile(profile))
        # Print profile summary for first user as example
        # if user_id == data_generator.user_ids[0]:
        #     print("\nExample Profile Summary:")
        #     print(f"User ID: {profile.user_id}")
        #     print(f"Last Updated: {profile.last_updated}")
        #     print(f"Risk Score: {profile.risk_score:.2f}")
        #     print("\nLogin Patterns:")
        #     print(
        #         f"Most common device: {max(profile.login_patterns['device_frequency'].items(), key=lambda x: x[1])[0]}"
        #     )
        #     print(
        #         f"Most common login method: {max(profile.login_patterns['login_method_frequency'].items(), key=lambda x: x[1])[0]}"
        #     )
        #     print("\nTransaction Patterns:")
        #     print(
        #         f"Average transaction amount: ${profile.transaction_patterns['amount_stats']['mean']:.2f}"
        #     )
        #     print(
        #         f"Most common transaction type: {max(profile.transaction_patterns['transaction_types'].items(), key=lambda x: x[1])[0]}"
        #     )
        #     print("\nFeature Usage Patterns:")
        #     print(
        #         f"Most used feature: {max(profile.feature_usage_patterns['feature_frequency'].items(), key=lambda x: x[1])[0]}"
        #     )

    # Save all profiles to CSV
    # project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # dataset_dir = os.path.join(project_root, "dataset")
    # os.makedirs(dataset_dir, exist_ok=True)
    # output_path = os.path.join(dataset_dir, "fraud_profiles.csv")
    # df = pd.DataFrame(all_profiles)
    # df.to_csv(output_path, index=False)
    # print(f"\nProcessed {len(data_generator.user_ids)} user profiles")
    # print(f"All profile data saved to {output_path}")


if __name__ == "__main__":
    main()
