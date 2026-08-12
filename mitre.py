MITRE_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries attempt to guess or crack account credentials "
            "through repeated login attempts."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": (
            "Adversaries use compromised but legitimate credentials to access "
            "systems, often evidenced by logins from anomalous locations or "
            "devices inconsistent with the account owner's normal behavior."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
}
def get_technique(technique_id):
    return MITRE_TECHNIQUES.get(technique_id)