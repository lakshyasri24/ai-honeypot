from flask import Flask, render_template, request
import sqlite3
from datetime import datetime
import subprocess
import sys

app = Flask(__name__)

DATABASE = "database/honeypot.db"


def init_database():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            action TEXT,
            timestamp TEXT,
            user_agent TEXT,
            risk_score INTEGER DEFAULT 0,
            behavior TEXT DEFAULT 'Unknown',
            severity TEXT DEFAULT 'LOW',
            ai_behavior TEXT
        )
    """)

    conn.commit()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        ip_address = request.remote_addr

        # Count previous attempts from the same IP
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM activities WHERE ip_address = ?",
            (ip_address,)
        )

        previous_attempts = cursor.fetchone()[0]

        conn.close()

        # Current attempt number
        attempt_count = previous_attempts + 1

        user_agent = request.headers.get("User-Agent")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Basic behaviour detection
        if attempt_count >= 10:
            behavior = "Brute Force"
            risk_score = 95
            severity = "HIGH"

        elif attempt_count >= 5:
            behavior = "Suspicious"
            risk_score = 70
            severity = "MEDIUM"

        else:
            behavior = "Normal"
            risk_score = 20
            severity = "LOW"

        # Save activity to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO activities
            (
                ip_address,
                username,
                action,
                timestamp,
                user_agent,
                risk_score,
                behavior,
                severity,
                ai_behavior
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip_address,
            username,
            "Login Attempt",
            timestamp,
            user_agent,
            risk_score,
            behavior,
            severity,
            "Not Analyzed"
        ))

        conn.commit()
        conn.close()

        # Automatically run AI behaviour analysis
        try:
            subprocess.run(
                [
                    sys.executable,
                    "ai/behaviour_model.py"
                ],
                check=True
            )

            print("AI behaviour analysis completed successfully.")

        except Exception as e:
            print("AI analysis error:", e)

        # Terminal activity information
        print("================================")
        print("HONEYPOT ACTIVITY RECORDED")
        print("IP Address:", ip_address)
        print("Username:", username)
        print("Attempt Count:", attempt_count)
        print("Behavior:", behavior)
        print("Risk Score:", risk_score)
        print("Severity:", severity)
        print("Time:", timestamp)
        print("================================")

        return "Login attempt recorded!"

    return render_template("login.html")


@app.route("/logs")
def logs():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM activities ORDER BY id DESC"
    )

    activities = cursor.fetchall()

    conn.close()

    return render_template(
        "logs.html",
        activities=activities
    )


@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Total activities
    cursor.execute(
        "SELECT COUNT(*) FROM activities"
    )

    total = cursor.fetchone()[0]

    # Unique IP addresses
    cursor.execute(
        "SELECT COUNT(DISTINCT ip_address) FROM activities"
    )

    unique_ips = cursor.fetchone()[0]

    # High risk events
    cursor.execute(
        "SELECT COUNT(*) FROM activities WHERE severity = 'HIGH'"
    )

    high_risk = cursor.fetchone()[0]

    # Suspicious events
    cursor.execute(
        "SELECT COUNT(*) FROM activities WHERE severity = 'MEDIUM'"
    )

    suspicious = cursor.fetchone()[0]

    # Recent activities including AI behaviour
    cursor.execute("""
        SELECT
            id,
            ip_address,
            username,
            action,
            timestamp,
            risk_score,
            behavior,
            severity,
            ai_behavior
        FROM activities
        ORDER BY id DESC
        LIMIT 20
    """)

    activities = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        unique_ips=unique_ips,
        high_risk=high_risk,
        suspicious=suspicious,
        activities=activities
    )


if __name__ == "__main__":
    init_database()
    app.run(host="0.0.0.0", port=5000, debug=True)