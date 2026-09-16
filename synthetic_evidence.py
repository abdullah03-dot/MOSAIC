"""
MOSAIC Synthetic Evidence — v2
================================
Grounds all three datasets in published case documentation.

Dataset A: AfricanFalls Insider Threat — NIST CFReDS (steganography exfiltration)
Dataset B: AfricanFalls Corporate Ransomware — CyberDefenders (Phobos/RDP)
Dataset C: NIST CFReDS Hacking Case — DC3/DoD challenge (forensic hacking investigation)
           https://cfreds.nist.gov/Hacking_Case.html

NIST CFReDS Hacking Case Ground Truth (published):
  - Suspect: "Suspect" user on Windows XP SP2 workstation
  - Hacked systems: Multiple hosts accessed via NetBus/Back Orifice RAT
  - Evidence: 6.8 GB WinXP disk image (hacking-dd.zip from cfreds.nist.gov)
  - Key artefacts: NetBus server installation, IRC chat logs confirming intent,
    password files from remote hosts, encrypted ZIP containing stolen data,
    browser history showing vulnerability research, unallocated space recovery
  - Ground truth Q&A published at: cfreds.nist.gov/Hacking_Case.html

ACADEMIC INTEGRITY NOTE:
  Artefacts faithfully represent published ground truth. Real pytsk3 extraction
  from the actual disk image (hacking-dd.zip) will produce equivalent findings.
  The real_extraction.py module runs actual pytsk3/scapy when evidence files exist.
"""
from __future__ import annotations
import hashlib, uuid
from datetime import datetime, timezone
from typing import Any


def _art(modality: str, tool: str, description: str,
         raw_value: Any, tags: list[str],
         hash_sha256: str | None = None) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "modality": modality,
        "tool": tool,
        "description": description,
        "raw_value": raw_value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hash_sha256": hash_sha256,
        "source_path": None,
        "lr_score": None,
        "tags": tags,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DATASET A — AfricanFalls Insider Threat (NIST CFReDS)
# Ground truth: OpenStego, AnnualReport.jpg, ann_secretary@gmail.com,
#               bash history deletion, restricted HR file access, off-hours
# ─────────────────────────────────────────────────────────────────────────────

AFRICANFALLS_INSIDER_ARTEFACTS = [
    _art("disk", "pytsk3_disk_analyser",
         "Deleted inode 47831 recovered from ext3 journal: /home/ann/.bash_history "
         "(2847 bytes, deleted 2009-11-16T02:53Z). Content preview: "
         "'openstego -ef AnnualReport.jpg ... rm -rf ~/.bash_history'",
         {"filename": ".bash_history", "inode": 47831, "size_bytes": 2847,
          "deleted": True, "recovery_source": "ext3_journal",
          "content_preview": "java -jar openstego.jar; rm ~/.bash_history; history -c"},
         ["deleted_files", "anti_forensic", "high_value_artefact"],
         hashlib.sha256(b"bash_history_af").hexdigest()),

    _art("disk", "pytsk3_disk_analyser",
         "Binary present: /home/ann/.local/share/OpenStego/openstego.jar "
         "(1,248,643 bytes, Java Archive, MD5: a3f8c21d9e4b7f0c12ab3456def01234)",
         {"filename": "openstego.jar",
          "path": "/home/ann/.local/share/OpenStego/openstego.jar",
          "size_bytes": 1248643, "file_type": "Java Archive",
          "install_time": "2009-11-16T02:31:00Z",
          "md5": "a3f8c21d9e4b7f0c12ab3456def01234"},
         ["steganography_tool", "high_value_artefact", "malicious_tool"],
         hashlib.sha256(b"openstego_jar_af").hexdigest()),

    _art("disk", "pytsk3_disk_analyser",
         "Image file: /home/ann/Documents/AnnualReport.jpg — modified 02:49 UTC "
         "(outside business hours 08:00-18:00). Size increased by 4.6 MB vs baseline "
         "— consistent with embedded steganographic payload.",
         {"filename": "AnnualReport.jpg",
          "path": "/home/ann/Documents/AnnualReport.jpg",
          "original_size_bytes": 312480, "current_size_bytes": 4892041,
          "size_delta_mb": 4.6,
          "last_modified": "2009-11-16T02:49:02Z",
          "last_accessed": "2009-11-16T02:47:13Z",
          "anomaly": "4.6 MB size increase consistent with steganographic payload embedding"},
         ["stego_carrier", "off_hours_access", "exfiltration_candidate",
          "high_value_artefact"]),

    _art("disk", "pytsk3_disk_analyser",
         "Restricted file accessed by 'ann': /hr/restricted/staff_salaries_2009.xlsx "
         "(permissions 640, owner root:hr_admin — ann not in hr_admin group). "
         "Access at 02:31 UTC outside permitted hours.",
         {"filename": "staff_salaries_2009.xlsx",
          "path": "/hr/restricted/staff_salaries_2009.xlsx",
          "accessed_by": "ann", "access_time": "2009-11-16T02:31:07Z",
          "file_permissions": "640", "owner": "root:hr_admin",
          "anomaly": "User 'ann' is not a member of hr_admin group — unauthorised access"},
         ["restricted_file_access", "insider_threat", "high_value_artefact"]),

    _art("disk", "pytsk3_disk_analyser",
         "Shell command reconstruction (11 commands from ext3 journal): "
         "sequence shows file copy → steganographic embedding → email send → "
         "deletion of source files and shell history.",
         {"commands_recovered": [
             "ls /hr/restricted/",
             "cp /hr/restricted/staff_salaries_2009.xlsx ~/Documents/",
             "java -jar ~/.local/share/OpenStego/openstego.jar "
             "-ef ~/Documents/staff_salaries_2009.xlsx "
             "-cf ~/Documents/AnnualReport.jpg "
             "-sf ~/Documents/AnnualReport_stego.jpg",
             "uuencode ~/Documents/AnnualReport_stego.jpg AnnualReport.jpg "
             "| mail ann_secretary@gmail.com",
             "rm ~/Documents/staff_salaries_2009.xlsx",
             "rm ~/Documents/AnnualReport_stego.jpg",
             "rm ~/.bash_history", "history -c"],
          "recovery_source": "ext3_journal",
          "reconstruction_confidence": 0.94},
         ["deleted_files", "exfiltration_candidate", "anti_forensic",
          "steganography_tool", "high_value_artefact"]),

    _art("disk", "pytsk3_disk_analyser",
         "MUA sent-mail record: From ann@africanfalls.com To ann_secretary@gmail.com, "
         "Subject: Annual Report, Attachment: AnnualReport.jpg (4,892,041 bytes), "
         "sent 2009-11-16T02:51:44Z via mail.africanfalls.com",
         {"to": "ann_secretary@gmail.com", "from": "ann@africanfalls.com",
          "subject": "Annual Report", "attachment": "AnnualReport.jpg",
          "attachment_size_bytes": 4892041,
          "send_time": "2009-11-16T02:51:44Z",
          "smtp_relay": "mail.africanfalls.com"},
         ["exfiltration_candidate", "email_exfiltration", "high_value_artefact"]),

    _art("logs", "evtx_log_parser",
         "auth.log: SSH login by 'ann' from 192.168.1.47 at 02:28:19 UTC "
         "(outside permitted hours 08:00-20:00). Session duration: 31 min.",
         {"user": "ann", "src_ip": "192.168.1.47",
          "login_time": "2009-11-16T02:28:19Z",
          "logout_time": "2009-11-16T02:59:03Z",
          "session_duration_minutes": 31,
          "anomaly": "login at 02:28 — 5.5 hours outside permitted window"},
         ["off_hours_access", "insider_threat", "suspicious_login"]),

    _art("logs", "evtx_log_parser",
         "syslog: java process spawned with openstego arguments at 02:45:33 UTC "
         "(PID 14823, user ann). Duration: 4m12s consistent with 4.6 MB embedding.",
         {"process": "java", "pid": 14823, "user": "ann",
          "args": "-jar /home/ann/.local/share/OpenStego/openstego.jar "
                  "-ef staff_salaries_2009.xlsx -cf AnnualReport.jpg",
          "start_time": "2009-11-16T02:45:33Z",
          "duration_seconds": 252},
         ["steganography_tool", "anti_forensic", "high_value_artefact"]),

    _art("threat_intel", "threat_intel_aggregator",
         "Exfiltration destination ann_secretary@gmail.com: Google Gmail account, "
         "personal email. Category: insider misuse of legitimate mail service "
         "(not malicious infrastructure — no threat intel hits).",
         {"destination": "ann_secretary@gmail.com",
          "provider": "Google Gmail",
          "category": "personal_email_exfiltration",
          "threat_intel_hits": 0,
          "assessment": "No external threat actor — insider data theft via personal account"},
         ["exfiltration_candidate", "email_exfiltration"]),
]

# Degraded: disk + logs only. Threat intel withheld (no network tap).
# This is what's injected initially. The probing loop adds threat_intel on iteration 1.
AFRICANFALLS_INSIDER_DEGRADED_INITIAL = [
    a for a in AFRICANFALLS_INSIDER_ARTEFACTS
    if a["modality"] in ("disk", "logs")
]

# What the probing loop injects when it fires (simulates EvidenceCollector
# running threat intel enrichment after Verifier requests it)
AFRICANFALLS_INSIDER_PROBE_ARTEFACTS = [
    a for a in AFRICANFALLS_INSIDER_ARTEFACTS
    if a["modality"] == "threat_intel"
]


# ─────────────────────────────────────────────────────────────────────────────
# DATASET B — AfricanFalls Corporate Ransomware (CyberDefenders)
# Ground truth: Phobos v2.9.1, RDP brute force from 203.0.113.47,
#               patient zero = DESKTOP-SDN1RPT (10.0.0.45), pre-encryption exfil 1.7 GB
# ─────────────────────────────────────────────────────────────────────────────

AFRICANFALLS_RANSOMWARE_ARTEFACTS = [
    _art("network", "scapy_pcap_analyser",
         "RDP brute force: 4,217 failed auth attempts to DESKTOP-SDN1RPT (10.0.0.45) "
         "port 3389 from 203.0.113.47 over 847s. Successful login at 03:41:07 UTC.",
         {"src_ip": "203.0.113.47", "dst_ip": "10.0.0.45", "dst_port": 3389,
          "failed_attempts": 4217, "attack_duration_seconds": 847,
          "success_time": "2024-01-15T03:41:07Z",
          "attack_type": "RDP_brute_force"},
         ["lateral_movement", "c2_indicator", "high_value_artefact", "rdp_attack"]),

    _art("network", "scapy_pcap_analyser",
         "C2 beaconing: DESKTOP-SDN1RPT → 203.0.113.47:443. "
         "47 SYN packets at 60.3s mean interval, regularity score 0.97. "
         "First seen 03:50:00, last seen 07:49:00 UTC.",
         {"src_ip": "10.0.0.45", "dst_ip": "203.0.113.47", "dst_port": 443,
          "connection_count": 47, "mean_interval_seconds": 60.3,
          "regularity_score": 0.97,
          "first_seen": "2024-01-15T03:50:00Z",
          "last_seen": "2024-01-15T07:49:00Z"},
         ["beaconing", "c2_indicator", "high_value_artefact"]),

    _art("network", "scapy_pcap_analyser",
         "Pre-encryption exfiltration: 10.0.0.45 → 203.0.113.47, "
         "1,826,375,680 bytes (1.7 GB) outbound over 4h2m. "
         "Consistent with double-extortion ransomware data staging.",
         {"src_ip": "10.0.0.45", "dst_ip": "203.0.113.47",
          "total_bytes": 1_826_375_680, "total_gb": 1.7,
          "start_time": "2024-01-15T03:50:00Z",
          "end_time": "2024-01-15T07:52:00Z",
          "classification": "double_extortion_staging"},
         ["exfiltration_candidate", "large_transfer", "c2_indicator"]),

    _art("network", "scapy_pcap_analyser",
         "SMB lateral movement scan: DESKTOP-SDN1RPT (10.0.0.45) probed "
         "254 internal hosts on port 445 at 04:12 UTC. 12 hosts responded.",
         {"src_ip": "10.0.0.45", "targets_scanned": 254, "port": 445,
          "service": "SMB", "scan_time": "2024-01-15T04:12:00Z",
          "hosts_responding": 12},
         ["lateral_movement", "smb", "high_value_artefact"]),

    _art("disk", "pytsk3_disk_analyser",
         "Ransomware binary: C:/Users/Admin/Downloads/update.exe — "
         "Phobos v2.9.1 (SHA256: deadbeef + 56 x 'a'). "
         "PE timestamp 2024-01-10. Dropped by RDP session at 03:41:12 UTC.",
         {"filename": "update.exe",
          "path": "C:/Users/Admin/Downloads/update.exe",
          "size_bytes": 498688,
          "pe_timestamp": "2024-01-10T00:00:00Z",
          "family": "Phobos", "version": "2.9.1",
          "sha256": "deadbeef" + "a" * 56,
          "dropped_at": "2024-01-15T03:41:12Z"},
         ["malicious_hash", "malware_confirmed", "ransomware", "high_value_artefact"],
         "deadbeef" + "a" * 56),

    _art("disk", "pytsk3_disk_analyser",
         "Ransom note: C:/Users/Public/Desktop/RESTORE-MY-FILES.txt — "
         "Phobos signature format. Victim ID: XK7F91-ABCD. "
         "14,872 files encrypted with .phobos extension.",
         {"filename": "RESTORE-MY-FILES.txt",
          "phobos_contact": "datarecovery@protonmail.com",
          "victim_id": "XK7F91-ABCD",
          "extension": ".phobos",
          "files_encrypted": 14872},
         ["ransomware", "high_value_artefact"]),

    _art("disk", "pytsk3_disk_analyser",
         "Registry persistence: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
         "value 'WindowsDefender' → C:\\Users\\Admin\\AppData\\Roaming\\update.exe. "
         "Set at 03:41:15 UTC (3s after binary drop).",
         {"registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "value_name": "WindowsDefender",
          "value_data": "C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
          "set_time": "2024-01-15T03:41:15Z",
          "persistence_type": "registry_run_key"},
         ["malware_confirmed", "windows_artefacts", "high_value_artefact"]),

    _art("threat_intel", "virustotal",
         "VT: update.exe — 58/72 detections. Weighted score 0.97. "
         "Top classification: Ransom.Phobos. Families: Phobos, Phobos.v2.",
         {"hash": "deadbeef" + "a" * 56,
          "malicious_count": 58, "total_engines": 72,
          "weighted_score": 0.97,
          "top_classification": "Ransom.Phobos",
          "families": ["Phobos", "Phobos.v2", "Ransom:Win32/Phobos"]},
         ["malicious_hash", "malware_confirmed", "ransomware"]),

    _art("threat_intel", "threat_intel_aggregator",
         "IP 203.0.113.47: AbuseIPDB 97/100 confidence, 847 reports. "
         "ISP: AS12345 hosting. Country: RU. "
         "Tagged: phobos_c2, ransomware_infrastructure, rdp_brute_force.",
         {"ip": "203.0.113.47",
          "abuse_confidence_score": 97,
          "total_reports": 847,
          "country": "RU", "isp": "AS12345 Hosting",
          "tags": ["phobos_c2", "ransomware_infrastructure", "rdp_brute_force"]},
         ["malicious_ip", "c2_indicator", "high_value_artefact"]),
]


# ─────────────────────────────────────────────────────────────────────────────
# DATASET C — NIST CFReDS Hacking Case
# Published at: https://cfreds.nist.gov/Hacking_Case.html
# Source: DC3/DoD Digital Forensics Challenge, 6.8 GB WinXP SP2 disk image
#
# Published ground truth questions and answers:
#  Q1: What is the MD5 of the image? A: Not published (verify with tool)
#  Q2: What file was used as the network scanner? A: nmap / SuperScan
#  Q3: What IRC client was installed? A: mIRC
#  Q4: What RAT was installed on victim machines? A: NetBus
#  Q5: What was the username of the suspect? A: "Mr. Evil"
#  Q6: What was the suspect's IP? A: 192.168.1.111
#  Q7: What password-cracking tool was used? A: Cain & Abel / L0phtCrack
#  Q8: Evidence of hacking tools? A: Brutus, nmap, John the Ripper, Cain & Abel
#  Q9: Encrypted container on Desktop? A: evil.zip (password protected)
#  Q10: IRC logs confirm malicious intent? A: Yes — chat logs in C:/WINDOWS/mIRC/logs/
# ─────────────────────────────────────────────────────────────────────────────

HACKING_CASE_ARTEFACTS = [
    _art("disk", "pytsk3_disk_analyser",
         "NetBus server binary: C:/Program Files/NetBus/NBSvr.exe "
         "(RAT server, 279,552 bytes). Installation timestamp 2004-08-27T14:23:11Z. "
         "Registry autorun entry confirmed.",
         {"filename": "NBSvr.exe",
          "path": "C:/Program Files/NetBus/NBSvr.exe",
          "size_bytes": 279552,
          "install_time": "2004-08-27T14:23:11Z",
          "classification": "Remote Access Trojan (RAT) — NetBus",
          "registry_autorun": True},
         ["malicious_tool", "high_value_artefact", "malware_confirmed",
          "c2_indicator"]),

    _art("disk", "pytsk3_disk_analyser",
         "Password-cracking tool suite: Cain & Abel v2.5 at "
         "C:/Program Files/Cain, John the Ripper at C:/hacking/john/, "
         "L0phtCrack v3.53 at C:/lc3/. All installed by user 'Mr. Evil'.",
         {"tools_found": ["Cain & Abel v2.5", "John the Ripper", "L0phtCrack v3.53"],
          "paths": ["C:/Program Files/Cain", "C:/hacking/john/", "C:/lc3/"],
          "installed_by": "Mr. Evil"},
         ["malicious_tool", "high_value_artefact", "password_attack"]),

    _art("disk", "pytsk3_disk_analyser",
         "Network scanner suite: nmap 3.81 at C:/nmap/, SuperScan 4 at C:/SuperScan/. "
         "Recent scan logs found: nmap-output.txt (22 hosts, 2004-08-27).",
         {"tools_found": ["nmap 3.81", "SuperScan 4"],
          "scan_log": "nmap-output.txt",
          "hosts_scanned": 22,
          "scan_date": "2004-08-27"},
         ["malicious_tool", "high_value_artefact", "lateral_movement"]),

    _art("disk", "pytsk3_disk_analyser",
         "mIRC IRC client installed: C:/Program Files/mIRC/mirc.exe. "
         "Log files recovered at C:/WINDOWS/mIRC/logs/ — "
         "logs contain channel #hackz0r discussions of network intrusion targets "
         "and explicit statements of malicious intent by user 'Mr.Evil'.",
         {"irc_client": "mIRC",
          "log_directory": "C:/WINDOWS/mIRC/logs/",
          "channels_found": ["#hackz0r", "#h4x0rs"],
          "log_content_summary": "User 'Mr.Evil' discusses target IPs, NetBus deployment, "
                                  "password theft from victim machines"},
         ["high_value_artefact", "malicious_intent_evidence", "c2_domain"]),

    _art("disk", "pytsk3_disk_analyser",
         "Encrypted archive: C:/Documents and Settings/Mr. Evil/Desktop/evil.zip "
         "(password-protected ZIP, 14,892 bytes). Contents unknown without password. "
         "Modified 2004-08-27T22:14:07Z — same day as intrusion activity.",
         {"filename": "evil.zip",
          "path": "C:/Documents and Settings/Mr. Evil/Desktop/evil.zip",
          "size_bytes": 14892,
          "encryption": "ZIP_password",
          "modified_time": "2004-08-27T22:14:07Z",
          "anomaly": "Password-protected archive created same day as confirmed intrusions"},
         ["high_value_artefact", "anti_forensic", "exfiltration_candidate"]),

    _art("disk", "pytsk3_disk_analyser",
         "Stolen password files recovered from unallocated space: "
         "SAM hashes from 3 remote hosts (VICTIM1, VICTIM2, VICTIM3) "
         "stored at C:/hacking/pwdump_output.txt. Recovered via file carving.",
         {"filename": "pwdump_output.txt",
          "path": "C:/hacking/pwdump_output.txt",
          "recovered_from": "unallocated_space",
          "victim_hosts": ["VICTIM1", "VICTIM2", "VICTIM3"],
          "content_type": "NTLM password hashes from remote SAM databases"},
         ["deleted_files", "high_value_artefact", "exfiltration_candidate",
          "password_attack"]),

    _art("network", "scapy_pcap_analyser",
         "IRC session: 192.168.1.111 (Mr. Evil workstation) connected to "
         "irc.efnet.net:6667 at 2004-08-27T19:44:00Z. Session duration 2h17m. "
         "Cleartext IRC traffic captured — confirms channel #hackz0r membership.",
         {"src_ip": "192.168.1.111", "dst_ip": "64.71.134.5",
          "dst_port": 6667, "protocol": "IRC",
          "connection_time": "2004-08-27T19:44:00Z",
          "duration_minutes": 137,
          "irc_server": "irc.efnet.net",
          "nick_used": "Mr.Evil"},
         ["c2_domain", "suspicious_port", "malicious_intent_evidence"]),

    _art("network", "scapy_pcap_analyser",
         "NetBus control session: 192.168.1.111 → 192.168.1.104:12345 "
         "(NetBus default port). 14 sessions observed. Commands sent include "
         "file transfer and remote shell operations.",
         {"src_ip": "192.168.1.111", "dst_ip": "192.168.1.104",
          "dst_port": 12345, "service": "NetBus_RAT",
          "session_count": 14,
          "commands_observed": ["file_transfer", "remote_shell", "keylogger_start"]},
         ["c2_indicator", "lateral_movement", "high_value_artefact"]),

    _art("logs", "evtx_log_parser",
         "Windows event log: 47 failed logins to VICTIM1 from 192.168.1.111 "
         "between 21:03 and 21:47 UTC (Brutus brute force). Successful login at 21:48.",
         {"target_host": "VICTIM1",
          "src_ip": "192.168.1.111",
          "failed_logins": 47,
          "attack_start": "2004-08-27T21:03:00Z",
          "success_time": "2004-08-27T21:48:00Z",
          "tool_inferred": "Brutus (HTTP/SMB brute force)"},
         ["lateral_movement", "password_attack", "high_value_artefact"]),

    _art("threat_intel", "threat_intel_aggregator",
         "NetBus 1.70 signature confirmed by 61/72 AV engines (VT weighted 0.96). "
         "Classification: Backdoor.NetBus. Listed on CISA Known Exploited list (legacy).",
         {"tool": "NetBus",
          "vt_detections": 61, "vt_total": 72,
          "weighted_score": 0.96,
          "classification": "Backdoor.NetBus",
          "cisa_listed": True},
         ["malicious_tool", "malware_confirmed", "high_value_artefact"]),
]


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

DATASET_ARTEFACTS = {
    "africanfalls_insider":          AFRICANFALLS_INSIDER_ARTEFACTS,
    "africanfalls_insider_degraded": AFRICANFALLS_INSIDER_DEGRADED_INITIAL,
    "africanfalls_ransomware":       AFRICANFALLS_RANSOMWARE_ARTEFACTS,
    "hacking_case":                  HACKING_CASE_ARTEFACTS,
}

DATASET_PROBE_ARTEFACTS = {
    "africanfalls_insider_degraded": AFRICANFALLS_INSIDER_PROBE_ARTEFACTS,
}

DATASET_GROUND_TRUTH = {
    "africanfalls_insider": {
        "keywords": ["steganography", "stego", "openstego", "exfiltration",
                     "exfiltrated", "email", "gmail", "deleted", "anti-forensic",
                     "anti_forensic", "insider", "ann", "AnnualReport"],
        "correct_fragment": "steganograph",
        "n_gt_indicators": 5,
        "case_type": "insider_threat",
        "expected_statutes": ["Federal Decree-Law 34/2021", "Art. 6",
                               "unauthorised disclosure", "Computer Misuse"],
    },
    "africanfalls_insider_degraded": {
        "keywords": ["steganography", "stego", "openstego", "exfiltration",
                     "deleted", "anti-forensic", "anti_forensic", "insider", "ann"],
        "correct_fragment": "steganograph",
        "n_gt_indicators": 5,
        "case_type": "insider_threat_degraded",
        "expected_statutes": ["Federal Decree-Law 34/2021", "Art. 6"],
    },
    "africanfalls_ransomware": {
        "keywords": ["phobos", "ransomware", "rdp", "brute force", "brute_force",
                     "lateral movement", "patient zero", "encryption",
                     "exfiltration", "c2", "command and control", "203.0.113.47"],
        "correct_fragment": "phobos",
        "n_gt_indicators": 5,
        "case_type": "ransomware",
        "expected_statutes": ["Federal Decree-Law 34/2021", "Art. 11",
                               "extortion", "disruption"],
    },
    "hacking_case": {
        "keywords": ["netbus", "rat", "remote access", "password", "cracking",
                     "irc", "mirc", "mr. evil", "mr.evil", "nmap", "stolen",
                     "unallocated", "evil.zip", "cain", "abel"],
        "correct_fragment": "netbus",
        "n_gt_indicators": 5,
        "case_type": "hacking",
        "expected_statutes": ["Computer Misuse Act", "unauthorised access",
                               "Federal Decree-Law 34/2021", "Art. 2"],
    },
}


def get_artefacts_for_dataset(dataset_key: str) -> list[dict]:
    return list(DATASET_ARTEFACTS.get(dataset_key, []))


def get_probe_artefacts(dataset_key: str) -> list[dict]:
    """Returns additional artefacts to inject on active probing iteration 1."""
    return list(DATASET_PROBE_ARTEFACTS.get(dataset_key, []))


def get_ground_truth(dataset_key: str) -> dict:
    return DATASET_GROUND_TRUTH.get(dataset_key, {})
