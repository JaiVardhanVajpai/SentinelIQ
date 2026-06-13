from datetime import datetime
from math import radians, sin, cos, sqrt, atan2


# ─────────────────────────────────────────
# CITY COORDINATES
# For impossible travel detection
# ─────────────────────────────────────────
CITY_COORDINATES = {
    "IN": (20.5937, 78.9629),   # India
    "US": (37.0902, -95.7129),  # United States
    "RU": (61.5240, 105.3188),  # Russia
    "CN": (35.8617, 104.1954),  # China
    "DE": (51.1657, 10.4515),   # Germany
    "GB": (55.3781, -3.4360),   # United Kingdom
    "BR": (-14.2350, -51.9253), # Brazil
    "NG": (9.0820, 8.6753),     # Nigeria
    "PK": (30.3753, 69.3451),   # Pakistan
    "UA": (48.3794, 31.1656),   # Ukraine
}

# Average travel speed in km/h
# Used to determine if travel is physically possible
TRAVEL_SPEED_KMH = 900  # approximate flight speed


# ─────────────────────────────────────────
# HELPER: Calculate distance between
# two countries using coordinates
# ─────────────────────────────────────────
def calculate_distance(country1: str, country2: str) -> float:
    """
    Calculate approximate distance in km
    between two countries using
    Haversine formula.
    Returns 0 if coordinates not found.
    """
    if country1 not in CITY_COORDINATES:
        return 0
    if country2 not in CITY_COORDINATES:
        return 0

    lat1, lon1 = CITY_COORDINATES[country1]
    lat2, lon2 = CITY_COORDINATES[country2]

    # Haversine formula
    R = 6371  # Earth radius in km
    lat1, lon1, lat2, lon2 = map(
        radians, [lat1, lon1, lat2, lon2]
    )
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c


# ─────────────────────────────────────────
# DETECTION RULE 1: Brute Force
# ─────────────────────────────────────────
def detect_brute_force(events: list) -> list:
    """
    Flag if same IP has 5+ failed logins
    within 10 minutes.
    Maps to MITRE T1110 - Brute Force
    """
    flagged = []

    # Group events by IP address
    ip_events = {}
    for event in events:
        ip = event.get("ip")
        if ip not in ip_events:
            ip_events[ip] = []
        ip_events[ip].append(event)

    # Check each IP
    for ip, ip_event_list in ip_events.items():

        # Get only failed logins
        failures = [
            e for e in ip_event_list
            if str(e.get("success", "")).lower()
            in ["false", "0", "no", "fail"]
        ]

        if len(failures) < 5:
            continue

        # Sort by time
        failures.sort(key=lambda x: x.get("timestamp", ""))

        # Check 10 minute windows
        for i in range(len(failures)):
            window = [failures[i]]
            t1 = datetime.fromisoformat(
                failures[i]["timestamp"]
            )

            for j in range(i + 1, len(failures)):
                t2 = datetime.fromisoformat(
                    failures[j]["timestamp"]
                )
                diff_minutes = (
                    t2 - t1
                ).total_seconds() / 60

                if diff_minutes <= 10:
                    window.append(failures[j])
                else:
                    break

            if len(window) >= 5:
                flagged.append({
                    "type": "brute_force",
                    "ip": ip,
                    "username": failures[i].get(
                        "username", "unknown"
                    ),
                    "failed_attempts": len(window),
                    "time_window_minutes": 10,
                    "first_attempt": failures[i][
                        "timestamp"
                    ],
                    "mitre_technique": "T1110",
                    "mitre_name": "Brute Force",
                    "severity": "HIGH",
                    "verdict": "MALICIOUS",
                    "explanation": (
                        f"IP {ip} made {len(window)} "
                        f"failed login attempts within "
                        f"10 minutes. This matches "
                        f"MITRE T1110 Brute Force pattern."
                    )
                })
                break

    return flagged


# ─────────────────────────────────────────
# DETECTION RULE 2: Impossible Travel
# ─────────────────────────────────────────
def detect_impossible_travel(events: list) -> list:
    """
    Flag if same user logs in successfully
    from two countries that are impossible
    to travel between in the time gap.
    Maps to MITRE T1078 - Valid Accounts
    """
    flagged = []

    # Group events by username
    user_events = {}
    for event in events:
        username = event.get("username")
        if username not in user_events:
            user_events[username] = []
        user_events[username].append(event)

    # Check each user
    for username, user_event_list in user_events.items():

        # Only successful logins
        successes = [
            e for e in user_event_list
            if str(e.get("success", "")).lower()
            in ["true", "1", "yes", "success"]
        ]

        if len(successes) < 2:
            continue

        # Sort by time
        successes.sort(
            key=lambda x: x.get("timestamp", "")
        )

        # Check consecutive logins
        for i in range(len(successes) - 1):
            e1 = successes[i]
            e2 = successes[i + 1]

            country1 = e1.get("country", "")
            country2 = e2.get("country", "")

            # Skip if same country
            if country1 == country2:
                continue

            # Calculate time difference
            t1 = datetime.fromisoformat(e1["timestamp"])
            t2 = datetime.fromisoformat(e2["timestamp"])
            hours_diff = (
                t2 - t1
            ).total_seconds() / 3600

            # Calculate distance
            distance_km = calculate_distance(
                country1, country2
            )

            if distance_km == 0:
                continue

            # Time needed to travel
            time_needed_hours = (
                distance_km / TRAVEL_SPEED_KMH
            )

            # Flag if impossible
            if hours_diff < time_needed_hours:
                flagged.append({
                    "type": "impossible_travel",
                    "username": username,
                    "login_1": {
                        "country": country1,
                        "timestamp": e1["timestamp"],
                        "ip": e1.get("ip", "unknown")
                    },
                    "login_2": {
                        "country": country2,
                        "timestamp": e2["timestamp"],
                        "ip": e2.get("ip", "unknown")
                    },
                    "distance_km": round(distance_km),
                    "time_available_hours": round(
                        hours_diff, 2
                    ),
                    "time_needed_hours": round(
                        time_needed_hours, 2
                    ),
                    "mitre_technique": "T1078",
                    "mitre_name": "Valid Accounts",
                    "severity": "CRITICAL",
                    "verdict": "MALICIOUS",
                    "explanation": (
                        f"User {username} logged in from "
                        f"{country1} and then {country2} "
                        f"within {round(hours_diff, 2)} hours. "
                        f"Distance is {round(distance_km)} km "
                        f"requiring at least "
                        f"{round(time_needed_hours, 2)} hours "
                        f"to travel. Physically impossible — "
                        f"indicates account compromise."
                    )
                })

    return flagged


# ─────────────────────────────────────────
# DETECTION RULE 3: Credential Stuffing
# ─────────────────────────────────────────
def detect_credential_stuffing(events: list) -> list:
    """
    Flag if same IP tries many different
    usernames — indicates credential stuffing
    attack using leaked password lists.
    Maps to MITRE T1110.004
    """
    flagged = []

    # Group by IP
    ip_usernames = {}
    for event in events:
        ip = event.get("ip")
        username = event.get("username")
        if ip not in ip_usernames:
            ip_usernames[ip] = set()
        ip_usernames[ip].add(username)

    # Flag if 3+ different usernames from one IP
    for ip, usernames in ip_usernames.items():
        if len(usernames) >= 3:
            flagged.append({
                "type": "credential_stuffing",
                "ip": ip,
                "unique_usernames_tried": len(usernames),
                "usernames": list(usernames),
                "mitre_technique": "T1110.004",
                "mitre_name": "Credential Stuffing",
                "severity": "HIGH",
                "verdict": "MALICIOUS",
                "explanation": (
                    f"IP {ip} attempted login with "
                    f"{len(usernames)} different usernames. "
                    f"This matches MITRE T1110.004 "
                    f"Credential Stuffing — attacker is "
                    f"using a leaked credentials list."
                )
            })

    return flagged


# ─────────────────────────────────────────
# MAIN FUNCTION — Run all detections
# ─────────────────────────────────────────
def analyze_login_events(events: list) -> dict:
    """
    Run all 3 detection rules on login events.
    Returns combined results with MITRE mapping.
    """

    brute_force = detect_brute_force(events)
    impossible_travel = detect_impossible_travel(events)
    credential_stuffing = detect_credential_stuffing(
        events
    )

    all_flagged = (
        brute_force + impossible_travel + credential_stuffing
    )

    # Overall verdict
    if any(
        f["severity"] == "CRITICAL" for f in all_flagged
    ):
        overall_verdict = "CRITICAL"
    elif len(all_flagged) > 0:
        overall_verdict = "SUSPICIOUS"
    else:
        overall_verdict = "CLEAN"

    return {
        "total_events_analyzed": len(events),
        "total_threats_detected": len(all_flagged),
        "overall_verdict": overall_verdict,
        "threats": all_flagged,
        "summary": {
            "brute_force_detected": len(brute_force),
            "impossible_travel_detected": len(
                impossible_travel
            ),
            "credential_stuffing_detected": len(
                credential_stuffing
            )
        }
    }