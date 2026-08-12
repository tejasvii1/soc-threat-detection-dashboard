import os
import requests
from dotenv import load_dotenv

load_dotenv()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:5000")
SEVERITY_EMBED_COLORS = {
    "CRITICAL": 0xDC2626,
    "HIGH": 0xF97316,
    "MEDIUM": 0xEAB308,
    "LOW": 0x3B82F6,
    "INFO": 0x6B7280,
}
def send_discord_alert(rule_name, severity, username, ip_address,
                        mitre_technique_id, mitre_technique_name,
                        triggered_at, details=None):
    if not DISCORD_WEBHOOK_URL:
        print("Discord webhook not configured — skipping notification.")
        return False
    embed = {
        "title": f"🚨 {rule_name} Detected",
        "color": SEVERITY_EMBED_COLORS.get(severity, 0x6B7280),
        "fields": [
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "Username", "value": username or "-", "inline": True},
            {"name": "IP Address", "value": ip_address or "-", "inline": True},
            {"name": "MITRE Technique", "value": f"{mitre_technique_id} - {mitre_technique_name}", "inline": False},
            {"name": "Triggered At", "value": triggered_at, "inline": False},
        ],
        "footer": {"text": "SOC Threat Detection Dashboard"},
    }
    if details:
        embed["description"] = details
    payload = {
        "content": f"New **{severity}** alert — [View Dashboard]({DASHBOARD_URL})",
        "embeds": [embed],
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"Failed to send Discord notification: {e}")
        return False