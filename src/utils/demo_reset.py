import argparse
import sys
from src.soc.alert_store import get_connection, initialize_database


def reset_demo_state(clear_all_demo_alerts: bool = False):
    """
    Controlled Demo State Reset Utility.
    Clears demo-generated incidents and alerts while preserving configuration,
    replay history, and threat intelligence indicators.
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    print("[*] Performing safe CyberSentinel Demo State Reset...")
    cursor.execute("DELETE FROM incident_timeline")
    cursor.execute("DELETE FROM incident_alerts")
    cursor.execute("DELETE FROM incidents")

    if clear_all_demo_alerts:
        cursor.execute("DELETE FROM alerts WHERE alert_id LIKE 'test_%' OR alert_id LIKE 'demo_%'")
        print("  - Cleared test and demo generated alerts.")

    conn.commit()
    conn.close()
    print("[+] Safe Demo Reset Complete. Database configuration & threat intelligence preserved.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSentinel Controlled Demo State Reset")
    parser.add_argument("--clear-demo-alerts", action="store_true", help="Also clear demo-generated alerts")
    args = parser.parse_args()

    reset_demo_state(clear_all_demo_alerts=args.clear_demo_alerts)
