from flask import Flask, render_template, request, redirect, url_for
from db import get_connection, get_event_count, get_alert_count, update_alert_status, ALERT_STATUSES, init_db
from mitre import get_technique

app = Flask(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
    "INFO": "#6b7280",
}
def ensure_demo_data():
    init_db()
    if get_event_count() == 0:
        from generate_logs import main as generate_logs_main
        from ingest import main as ingest_main
        from detect import main as detect_main

        print("Database empty — seeding demo data...")
        generate_logs_main()
        ingest_main()
        detect_main()
        print("Demo data seeded.")


ensure_demo_data()
@app.route("/")
def dashboard():
    search = request.args.get("q", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    rule_filter = request.args.get("rule", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    alert_query = "SELECT * FROM alerts WHERE 1=1"
    alert_params = []

    if search:
        alert_query += " AND (username LIKE ? OR ip_address LIKE ?)"
        alert_params.extend([f"%{search}%", f"%{search}%"])
    if severity_filter:
        alert_query += " AND severity = ?"
        alert_params.append(severity_filter)
    if rule_filter:
        alert_query += " AND rule_name = ?"
        alert_params.append(rule_filter)
    if start_date:
        alert_query += " AND date(triggered_at) >= date(?)"
        alert_params.append(start_date)
    if end_date:
        alert_query += " AND date(triggered_at) <= date(?)"
        alert_params.append(end_date)

    alert_query += " ORDER BY triggered_at DESC"

    event_query = "SELECT * FROM events WHERE 1=1"
    event_params = []
    if search:
        event_query += " AND (username LIKE ? OR ip_address LIKE ?)"
        event_params.extend([f"%{search}%", f"%{search}%"])
    event_query += " ORDER BY timestamp DESC LIMIT 50"

    with get_connection() as conn:
        alerts = conn.execute(alert_query, alert_params).fetchall()
        recent_events = conn.execute(event_query, event_params).fetchall()
        high_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'").fetchone()[0]
        critical_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'").fetchone()[0]
        rule_names = [r[0] for r in conn.execute("SELECT DISTINCT rule_name FROM alerts").fetchall()]

    metrics = {
        "total_events": get_event_count(),
        "total_alerts": get_alert_count(),
        "high_count": high_count,
        "critical_count": critical_count,
    }

    alerts_with_mitre = []
    for alert in alerts:
        alert_dict = dict(alert)
        technique = get_technique(alert_dict.get("mitre_technique_id"))
        alert_dict["mitre_url"] = technique["url"] if technique else None
        alerts_with_mitre.append(alert_dict)

    return render_template(
        "dashboard.html",
        metrics=metrics,
        alerts=alerts_with_mitre,
        events=recent_events,
        severity_colors=SEVERITY_COLORS,
        alert_statuses=ALERT_STATUSES,
        rule_names=rule_names,
        filters={
            "q": search,
            "severity": severity_filter,
            "rule": rule_filter,
            "start_date": start_date,
            "end_date": end_date,
        },
    )
@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_status(alert_id):
    new_status = request.form.get("status")
    try:
        update_alert_status(alert_id, new_status)
    except ValueError:
        pass
    return redirect(url_for("dashboard"))
if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")