from typing import Any, Dict, List, Optional

# Official MITRE ATT&CK Enterprise Dataset Version
ATTACK_VERSION = "19.0"
ATTACK_DATASET_SOURCE = f"MITRE ATT&CK Enterprise v{ATTACK_VERSION} (STIX v2.1 Package)"


# Official ATT&CK Enterprise Mappings for CyberSentinel Detections
ATTACK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "SSH-Bruteforce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "mapping_status": "MAPPED",
        "confidence": 0.88,
        "rationale": "Associated ATT&CK technique: Repeated SSH authentication-oriented network activity detected.",
    },
    "FTP-BruteForce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "mapping_status": "MAPPED",
        "confidence": 0.88,
        "rationale": "Associated ATT&CK technique: Repeated FTP authentication-oriented network activity detected.",
    },
    "Brute Force -Web": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "mapping_status": "MAPPED",
        "confidence": 0.85,
        "rationale": "Associated ATT&CK technique: Automated web form password guessing attempts.",
    },
    "Brute Force -XSS": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "mapping_status": "MAPPED",
        "confidence": 0.85,
        "rationale": "Associated ATT&CK technique: Web application authentication probing and payload injection.",
    },
    "DoS attacks-Hulk": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.85,
        "rationale": "Associated ATT&CK technique: High-volume application HTTP GET resource exhaustion detected.",
    },
    "DoS attacks-Slowloris": {
        "technique_id": "T1498.002",
        "technique_name": "Reflection Amplification / Low & Slow DoS",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.87,
        "rationale": "Associated ATT&CK technique: Low & Slow socket connection exhaustion attack.",
    },
    "DoS attacks-GoldenEye": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.85,
        "rationale": "Associated ATT&CK technique: Web server connection pool starvation attempt.",
    },
    "DoS attacks-SlowHTTPTest": {
        "technique_id": "T1498.002",
        "technique_name": "Reflection Amplification / Low & Slow DoS",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.87,
        "rationale": "Associated ATT&CK technique: Incomplete HTTP header connection persistence attack.",
    },
    "DDOS attack-HOIC": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.90,
        "rationale": "Associated ATT&CK technique: High-yield direct HTTP request flooding detected.",
    },
    "DDoS attacks-LOIC-HTTP": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.90,
        "rationale": "Associated ATT&CK technique: Multi-threaded HTTP web request flooding detected.",
    },
    "DDOS attack-LOIC-UDP": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "mapping_status": "MAPPED",
        "confidence": 0.90,
        "rationale": "Associated ATT&CK technique: UDP packet flood targeting host application ports.",
    },
    "Bot": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "mapping_status": "MAPPED",
        "confidence": 0.80,
        "rationale": "Associated ATT&CK technique: Automated botnet command and control communication traffic.",
    },
    "Infilteration": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "mapping_status": "MAPPED",
        "confidence": 0.82,
        "rationale": "Associated ATT&CK technique: Potential internal network intrusion or perimeter breach activity.",
    },
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "mapping_status": "MAPPED",
        "confidence": 0.82,
        "rationale": "Associated ATT&CK technique: Malicious database query injection targeting public web services.",
    },
}


class MitreAttackEngine:
    """
    MITRE ATT&CK Enterprise v19.0 Integration for CyberSentinel (Phase 3B).
    Maps defensive detection events to ATT&CK tactics, techniques, and rationales.
    """

    @staticmethod
    def get_mitre_mapping(attack_type: str, rule_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        mapping = ATTACK_MAPPINGS.get(attack_type)

        if not mapping:
            return {
                "attack_type": attack_type,
                "technique_id": None,
                "technique_name": None,
                "tactic_id": None,
                "tactic_name": None,
                "mapping_status": "UNMAPPED",
                "confidence": 0.0,
                "rationale": "No defensive network evidence to map to specific ATT&CK technique.",
                "source": ATTACK_DATASET_SOURCE,
                "attack_version": ATTACK_VERSION,
            }

        res = dict(mapping)
        res["attack_type"] = attack_type
        res["source"] = ATTACK_DATASET_SOURCE
        res["attack_version"] = ATTACK_VERSION
        return res

    @staticmethod
    def list_techniques() -> List[Dict[str, Any]]:
        techniques = {}
        for atk, data in ATTACK_MAPPINGS.items():
            tid = data["technique_id"]
            if tid not in techniques:
                techniques[tid] = {
                    "technique_id": tid,
                    "technique_name": data["technique_name"],
                    "tactic_id": data["tactic_id"],
                    "tactic_name": data["tactic_name"],
                    "associated_attacks": [atk],
                    "confidence": data["confidence"],
                }
            else:
                techniques[tid]["associated_attacks"].append(atk)

        return list(techniques.values())

    @staticmethod
    def list_tactics() -> List[Dict[str, Any]]:
        tactics = {}
        for atk, data in ATTACK_MAPPINGS.items():
            tacid = data["tactic_id"]
            if tacid not in tactics:
                tactics[tacid] = {
                    "tactic_id": tacid,
                    "tactic_name": data["tactic_name"],
                    "techniques_count": 1,
                }
            else:
                tactics[tacid]["techniques_count"] += 1
        return list(tactics.values())

    @staticmethod
    def get_coverage() -> Dict[str, Any]:
        mapped_count = len(ATTACK_MAPPINGS)
        tactics = set(d["tactic_id"] for d in ATTACK_MAPPINGS.values())
        techniques = set(d["technique_id"] for d in ATTACK_MAPPINGS.values())

        return {
            "attack_version": ATTACK_VERSION,
            "dataset_source": ATTACK_DATASET_SOURCE,
            "mapped_detections": mapped_count,
            "mapped_tactics_count": len(tactics),
            "mapped_techniques_count": len(techniques),
            "tactics": sorted(list(tactics)),
            "techniques": sorted(list(techniques)),
        }
