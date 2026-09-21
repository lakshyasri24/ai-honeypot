import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest

DATABASE = "database/honeypot.db"


def load_data():

    conn = sqlite3.connect(DATABASE)

    query = """
        SELECT
            id,
            ip_address,
            username,
            risk_score,
            timestamp
        FROM activities
    """

    df = pd.read_sql_query(query, conn)

    conn.close()

    return df


def analyze_behavior():

    df = load_data()

    if len(df) < 5:
        print("Not enough data for AI analysis.")
        print("At least 5 activities are required.")
        return

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Sort by IP and timestamp
    df = df.sort_values(["ip_address", "timestamp"])

    # Count attempts from each IP
    df["attempt_count"] = (
        df.groupby("ip_address")["ip_address"]
        .transform("count")
    )

    # Time difference between attempts
    df["time_difference"] = (
        df.groupby("ip_address")["timestamp"]
        .diff()
        .dt.total_seconds()
    )

    df["time_difference"] = df["time_difference"].fillna(9999)

    # ML features
    features = df[
        [
            "attempt_count",
            "risk_score",
            "time_difference"
        ]
    ]

    # AI anomaly detection
    model = IsolationForest(
        contamination=0.2,
        random_state=42
    )

    model.fit(features)

    df["ai_prediction"] = model.predict(features)

    # Combined security decision
    def classify(row):

        risk = row["risk_score"]
        time_gap = row["time_difference"]
        ai_result = row["ai_prediction"]

        # High-risk behaviour
        if risk >= 70:
            return "HIGH RISK"

        # Very rapid repeated activity
        if time_gap <= 30 and risk >= 20:
            return "SUSPICIOUS"

        # AI anomaly
        if ai_result == -1:
            return "SUSPICIOUS"

        return "NORMAL"

    df["final_behavior"] = df.apply(classify, axis=1)

    # Save AI results to database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    for _, row in df.iterrows():

        cursor.execute(
            """
            UPDATE activities
            SET ai_behavior = ?
            WHERE id = ?
            """,
            (
                row["final_behavior"],
                int(row["id"])
            )
        )

    conn.commit()
    conn.close()

    # Display results
    print("\n========== AI BEHAVIOR ANALYSIS ==========\n")

    print(
        df[
            [
                "id",
                "ip_address",
                "username",
                "attempt_count",
                "risk_score",
                "time_difference",
                "final_behavior"
            ]
        ].to_string(index=False)
    )

    print("\nAI results saved to database successfully.")
    print("\n==========================================\n")


if __name__ == "__main__":
    analyze_behavior()