# SSH FORENSIC LOG ANALYZER
### A Python-Based Digital Forensic Investigation Project

**Project Title:** SSH Forensic Log Analyzer for Suspicious Login Detection   
**Domain:** Digital Forensics and Cybersecurity  
**Programming Language:** Python 3  
**Development Environment:** Visual Studio Code  
**Operating System:** Windows 11  
**Project Type:** Educational Digital Forensics Project

# 1. ABSTRACT
The SSH Forensic Log Analyzer is a Python-based digital forensic project developed to examine Secure Shell (SSH) authentication log files and identify potentially suspicious login activities.
Secure Shell (SSH) is a network protocol used to establish secure remote connections between computers. SSH authentication logs maintain records of login activities, including failed authentication attempts, successful logins, timestamps, usernames, and source IP addresses.
Repeated failed login attempts from a particular IP address may indicate password guessing or brute-force activity. Manual examination of large log files can be time-consuming. Therefore, this project uses Python to automate log reading, parsing, analysis, suspicious IP detection, file hashing, and report generation.
The system generates structured CSV records, a text-based forensic summary, a graphical login activity report, and a JSON-based chain-of-custody demonstration record.
This project demonstrates how basic Python programming concepts and open-source libraries can support preliminary digital forensic log examination.

# 2. INTRODUCTION

Digital forensics involves the identification, preservation, examination, analysis, and presentation of digital evidence.

System logs are important sources of digital evidence because they record activities performed on computer systems and networks.

SSH authentication logs can help investigators examine:
- Failed login attempts.
- Successful login attempts.
- Usernames associated with authentication events.
- Source IP addresses.
- Repeated authentication failures.
- Potentially suspicious login patterns.

This project focuses on automated examination of SSH authentication logs using Python.
The system processes a sample log file and identifies IP addresses that exceed a predefined failed-login threshold.

# 3. AIM OF THE PROJECT

To develop a Python-based forensic log analysis tool that examines SSH authentication records, identifies repeated failed login attempts, verifies file integrity using SHA-256 hashing, and generates structured forensic reports.

# 4. OBJECTIVES

1. To read SSH authentication log files.
2. To extract relevant information from raw log records.
3. To identify failed and successful login attempts.
4. To extract usernames and source IP addresses.
5. To validate IP address formats.
6. To count failed login attempts for each IP address.
7. To flag IP addresses exceeding the defined threshold.
8. To calculate SHA-256 hash values.
9. To generate CSV, TXT, PNG, and JSON reports.
10. To test individual project functions using Python unit testing.

# 5. SOFTWARE AND TECHNOLOGIES USED

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| Visual Studio Code | Code development |
| pathlib | File and folder path handling |
| re | Regular expression-based log parsing |
| ipaddress | IP address validation |
| collections.Counter | Counting failed login attempts |
| hashlib | SHA-256 hash calculation |
| csv | Generating structured CSV records |
| json | Generating a JSON record |
| Matplotlib | Creating login activity charts |
| unittest | Testing project functions |

All the libraries used apart from Matplotlib are included in Python's standard library.

# 6. SYSTEM REQUIREMENTS

**Hardware requirements**
- Windows 11 computer or compatible system.
- Minimum 4 GB RAM recommended.
- Sufficient storage for the dataset and generated reports.
- Internet connection for installing Matplotlib.

**Software requirements**
- Python 3.12 or compatible Python 3 version.
- Visual Studio Code.
- Matplotlib Python library.

# 7. PROJECT DIRECTORY STRUCTURE

```text
SSH_Forensic_Log_Analyzer_Final/
│
├── Dataset/
│   └── ssh_auth.log
│
├── Output/
│
├── src/
│   ├── __init__.py
│   ├── log_reader.py
│   ├── log_parser.py
│   ├── log_analyzer.py
│   ├── hash_checker.py
│   └── report_generator.py
│
├── main.py
├── test_project.py
├── requirements.txt
└── README.md
```

**Folder descriptions**

**Dataset:** Contains the sample SSH authentication log file.

**Output:** Stores the reports generated after analysis.

**src:** Contains individual Python modules responsible for reading, parsing, analyzing, hashing, and reporting.

**main.py:** Executes the complete project workflow.

**test_project.py:** Contains unit tests for checking project functionality.

**requirements.txt:** Lists the external Python library required.

**README.md:** Contains project documentation and source code.

# 8. SAMPLE DATASET

The project uses a synthetic SSH authentication log file created specifically for educational testing.

File name: `ssh_auth.log`

Location: `Dataset/ssh_auth.log`

Sample records:
```text
Nov 03 09:00:01 server sshd[1001]: Failed password for admin from 192.168.1.10 port 5001 ssh2
Nov 03 09:00:05 server sshd[1002]: Failed password for admin from 192.168.1.10 port 5002 ssh2
Nov 03 09:00:09 server sshd[1003]: Failed password for root from 192.168.1.10 port 5003 ssh2
Nov 03 09:00:13 server sshd[1004]: Failed password for test from 192.168.1.10 port 5004 ssh2
Nov 03 09:00:17 server sshd[1005]: Failed password for user from 192.168.1.10 port 5005 ssh2
Nov 03 09:05:20 server sshd[1006]: Accepted password for admin from 192.168.1.15 port 5006 ssh2
Nov 03 09:10:30 server sshd[1007]: Failed password for guest from 192.168.1.20 port 5007 ssh2
Nov 03 09:10:35 server sshd[1008]: Failed password for guest from 192.168.1.20 port 5008 ssh2
```
**Dataset interpretation**

The sample dataset contains:
- Five failed login attempts from 192.168.1.10.
- One successful login from 192.168.1.15.
- Two failed login attempts from 192.168.1.20.
The IP address 192.168.1.10 exceeds the configured threshold of three failed attempts and is therefore flagged for further investigation.

# 9. PROJECT WORKING METHODOLOGY

The project follows five major stages.

**Stage 1 – Log Reading**

The program opens the SSH log file, reads its contents, and removes empty lines.

**Stage 2 – Log Parsing**

Regular expressions extract timestamps, host information, process IDs, usernames, event types, and IP addresses.

**Stage 3 – Log Analysis**

The program separates failed and successful authentication events and counts failed attempts for individual IP addresses.

**Stage 4 – File Integrity Verification**

The program calculates the SHA-256 hash of the original dataset.

**Stage 5 – Report Generation**

The program generates CSV, TXT, PNG, and JSON output files.

# 10. COMPLETE SOURCE CODE AND MODULE EXPLANATION

## MODULE 1: log_reader.py

**Location:** `src/log_reader.py`

**Purpose:** Reads the SSH authentication log file and returns non-empty records.
```python
from pathlib import Path


def read_log_file(file_path):
    """Read a log file and return non-empty lines."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        return [line.strip() for line in log_file if line.strip()]
```

**Code explanation**

- `Path` handles file paths.
- `exists()` checks whether the file is available.
- `open()` opens the file in read mode.
- `encoding="utf-8"` specifies the text encoding.
- `errors="replace"` handles characters that cannot be decoded.
- `strip()` removes unnecessary spaces and line endings.
- Empty lines are excluded from the returned list.

**Forensic significance:** This module provides the initial access to the source log records for examination.

## MODULE 2: log_parser.py

**Location:** `src/log_parser.py`

**Purpose:** Extracts structured information from raw SSH log records.

```python
import re
import ipaddress


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)


def parse_log_line(line):
    match = LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    if "Failed password" in message:
        event = "failed"
    elif "Accepted password" in message:
        event = "success"
    else:
        event = "other"

    user_match = re.search(
        r"(?:for invalid user|for)\s+(\S+)", message
    )
    ip_match = re.search(r"\bfrom\s+(\S+)", message)

    username = user_match.group(1) if user_match else "unknown"
    source_ip = ip_match.group(1) if ip_match else "unknown"

    try:
        ipaddress.ip_address(source_ip)
        valid_ip = True
    except ValueError:
        valid_ip = False

    return {
        "timestamp": data["timestamp"],
        "host": data["host"],
        "process_id": data["pid"],
        "event": event,
        "username": username,
        "source_ip": source_ip,
        "valid_ip": valid_ip,
        "raw_message": message,
    }


def parse_log_lines(lines):
    parsed = []

    for line in lines:
        event = parse_log_line(line)

        if event is not None:
            parsed.append(event)

    return parsed
```

**Code explanation**

- `re` is used for pattern matching.
- `LOG_PATTERN` identifies the general SSH log structure.
- `groupdict()` extracts named fields.
- Failed authentication events are labelled `failed`.
- Successful authentication events are labelled `success`.
- Other recognised SSH messages are labelled `other`.
- Username and IP address are extracted using regular expressions.
- `ipaddress.ip_address()` checks whether the extracted IP is valid.
- The function returns structured information as a Python dictionary.
- `parse_log_lines()` processes multiple log records.

**Forensic significance:** Converts raw text into structured records that can be examined and compared systematically.

## MODULE 3: log_analyzer.py

**Location:** `src/log_analyzer.py`

**Purpose:** Examines authentication records and identifies IP addresses with repeated failed login attempts.

```python
from collections import Counter


def analyze_events(events, threshold=3):

    failed_events = [
        event for event in events
        if event["event"] == "failed"
    ]

    successful_events = [
        event for event in events
        if event["event"] == "success"
    ]

    failures_by_ip = Counter(
        event["source_ip"]
        for event in failed_events
        if event["valid_ip"]
    )

    suspicious_ips = {
        ip: count
        for ip, count in failures_by_ip.items()
        if count > threshold
    }

    return {
        "total_events": len(events),
        "failed_logins": len(failed_events),
        "successful_logins": len(successful_events),
        "other_events": sum(
            1 for event in events if event["event"] == "other"
        ),
        "invalid_ip_events": sum(
            1 for event in events if not event["valid_ip"]
        ),
        "failures_by_ip": dict(failures_by_ip),
        "suspicious_ips": suspicious_ips,
        "threshold": threshold,
    }
```

**Code explanation**

- Failed and successful events are separated.
- `Counter()` calculates the number of failed attempts for each valid source IP.
- The threshold is set to three.
- An IP is flagged when its failed attempts are greater than three.
- Summary statistics are returned as a dictionary.

**Detection rule**

```text
If failed login attempts > 3:
    Flag the IP address.
Otherwise:
    Do not flag the IP address.
```

**Forensic significance:** Helps identify repeated authentication failures that may warrant further investigation.

## MODULE 4: hash_checker.py

**Location:** `src/hash_checker.py`

**Purpose:** Calculates SHA-256 hash values and compares hash strings.

```python
import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""

    digest = hashlib.sha256()

    with Path(file_path).open("rb") as source:
        for block in iter(lambda: source.read(4096), b""):
            digest.update(block)

    return digest.hexdigest()


def compare_hashes(original_hash, current_hash):
    """Compare two SHA-256 hash values."""

    return original_hash.lower() == current_hash.lower()
```

**Code explanation**

- `hashlib` provides cryptographic hash functions.
- `sha256()` creates a SHA-256 hash object.
- The file is opened in binary read mode.
- Data is read in blocks of 4096 bytes.
- `update()` adds each block to the hash calculation.
- `hexdigest()` returns the final hash as a hexadecimal string.
- `compare_hashes()` compares two hash strings without case sensitivity.

**Forensic significance:** A matching SHA-256 hash supports the conclusion that the compared file contents are identical at the time of comparison. It does not independently establish authenticity or prove that a file was never altered before the baseline was created.

## MODULE 5: report_generator.py

**Location:** `src/report_generator.py`

**Purpose:** Generates structured analysis reports and a login activity chart.

```python
import csv
import json
from pathlib import Path
import matplotlib.pyplot as plt


def generate_reports(events, analysis, source_hash, output_dir):

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Generate parsed events CSV
    csv_path = output_path / "parsed_events.csv"

    fieldnames = [
        "timestamp", "host", "process_id", "event",
        "username", "source_ip", "valid_ip", "raw_message"
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    # Generate summary report
    summary_path = output_path / "summary_report.txt"

    with summary_path.open("w", encoding="utf-8") as report:
        report.write("SSH FORENSIC LOG ANALYSIS SUMMARY\n")
        report.write("=" * 36 + "\n")
        report.write(f"Total events: {analysis['total_events']}\n")
        report.write(f"Failed logins: {analysis['failed_logins']}\n")
        report.write(f"Successful logins: {analysis['successful_logins']}\n")
        report.write(f"Other events: {analysis['other_events']}\n")
        report.write(f"Invalid IP events: {analysis['invalid_ip_events']}\n")
        report.write(f"Failure threshold: more than {analysis['threshold']}\n")

        report.write("\nFlagged IP addresses:\n")

        if analysis["suspicious_ips"]:
            for ip, count in analysis["suspicious_ips"].items():
                report.write(f"- {ip}: {count} failed attempts\n")
        else:
            report.write("- None\n")

        report.write(f"\nSource log SHA-256: {source_hash}\n")

    # Generate login activity chart
    chart_path = output_path / "login_analysis.png"

    labels = ["Failed", "Successful"]
    values = [
        analysis["failed_logins"],
        analysis["successful_logins"]
    ]

    plt.figure(figsize=(7, 4))
    bars = plt.bar(labels, values)
    plt.title("SSH Login Activity")
    plt.ylabel("Number of events")
    plt.bar_label(bars)
    plt.tight_layout()
    plt.savefig(chart_path, dpi=150)
    plt.close()

    # Generate chain-of-custody demonstration JSON
    custody_path = output_path / "chain_of_custody.json"

    custody = {
        "source_file": "Dataset/ssh_auth.log",
        "sha256": source_hash,
        "record_type": "educational demonstration",
        "note": "Record actual handler, date/time, transfer and storage details in a real case."
    }

    with custody_path.open("w", encoding="utf-8") as json_file:
        json.dump(custody, json_file, indent=4)

    return {
        "csv": str(csv_path),
        "summary": str(summary_path),
        "chart": str(chart_path),
        "custody": str(custody_path),
    }
```

**Code explanation**

- `csv` creates structured tabular records.
- `json` creates a structured custody demonstration record.
- `Path` manages the output folder and file paths.
- `matplotlib.pyplot` generates the login activity chart.
- `mkdir()` creates the Output folder if it does not already exist.
- The CSV contains the parsed SSH events.
- The TXT file contains the analysis summary.
- The PNG file visualises failed and successful logins.
- The JSON file records the source file path and its SHA-256 value.

**Forensic significance:** Produces organised outputs that can be reviewed during preliminary examination and included in a technical report.

## MODULE 6: main.py

**Location:** Project root folder.

**Purpose:** Connects all the modules and executes the complete analysis.

```python
from pathlib import Path

from src.log_reader import read_log_file
from src.log_parser import parse_log_lines
from src.log_analyzer import analyze_events
from src.hash_checker import calculate_sha256
from src.report_generator import generate_reports


def main():

    project_dir = Path(__file__).resolve().parent

    dataset_file = project_dir / "Dataset" / "ssh_auth.log"
    output_dir = project_dir / "Output"

    print("[1/5] Reading SSH log...")
    raw_lines = read_log_file(dataset_file)

    print("[2/5] Parsing log events...")
    events = parse_log_lines(raw_lines)

    print("[3/5] Analyzing login activity...")
    analysis = analyze_events(events, threshold=3)

    print("[4/5] Calculating SHA-256...")
    source_hash = calculate_sha256(dataset_file)

    print("[5/5] Generating reports...")
    outputs = generate_reports(
        events, analysis, source_hash, output_dir
    )

    print("\n========== ANALYSIS RESULTS ==========")
    print(f"Total events       : {analysis['total_events']}")
    print(f"Failed logins      : {analysis['failed_logins']}")
    print(f"Successful logins  : {analysis['successful_logins']}")
    print(f"Invalid IP events  : {analysis['invalid_ip_events']}")

    print("\nFlagged IP addresses:")

    if analysis["suspicious_ips"]:
        for ip, count in analysis["suspicious_ips"].items():
            print(f"{ip} -> {count} failed attempts")
    else:
        print("None")

    print(f"\nSHA-256: {source_hash}")

    print("\nGenerated files:")

    for name, path in outputs.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
```

**Code explanation**

1. Imports all the project modules.
2. Identifies the project directory.
3. Locates the input dataset.
4. Reads the raw SSH records.
5. Parses the log entries.
6. Analyses authentication activity.
7. Calculates the source file's SHA-256 hash.
8. Generates all output reports.
9. Displays the analysis results in the terminal.

# 11. REQUIREMENTS FILE

File name: `requirements.txt`
```text
matplotlib
```
Installation command:
```bash
python -m pip install -r requirements.txt
```

# 12. HOW TO EXECUTE THE PROJECT

**Step 1:** Open the project folder in Visual Studio Code.

**Step 2:** Open the integrated terminal using:
```text
Ctrl + `
```

**Step 3:** Install the required library:
```bash
python -m pip install -r requirements.txt
```

**Step 4:** Execute the main program:
```bash
python main.py
```

**Step 5:** Check the generated reports inside the Output folder.

# 13. EXPECTED ANALYSIS RESULTS

For the supplied eight-record synthetic dataset, the expected results are:

| Parameter | Expected result |
|---|---:|
| Total events | 8 |
| Failed logins | 7 |
| Successful logins | 1 |
| Other events | 0 |
| Invalid IP events | 0 |
| Flagged IP addresses | 1 |
| Failed attempts from 192.168.1.10 | 5 |

**Flagged IP:** `192.168.1.10`

**Reason:** Five failed login attempts, exceeding the configured threshold of three.
The actual SHA-256 value is generated at runtime and depends on the exact bytes of the dataset file.

# 14. GENERATED OUTPUT FILES

The Output folder contains the following files.

**1. parsed_events.csv**

Contains structured SSH authentication records, including timestamps, usernames, event types, and IP addresses.

**2. summary_report.txt**

Contains total events, failed logins, successful logins, invalid IP events, flagged IP addresses, and the source SHA-256 value.

**3. login_analysis.png**

A graphical representation of failed and successful authentication attempts.

**4. chain_of_custody.json**

A basic educational demonstration record containing the source file path and SHA-256 hash.

# 15. UNIT TESTING
The project can be tested using Python's built-in unittest framework.

Create a file named `test_project.py` in the main project folder.
```python
import tempfile
import unittest
from pathlib import Path

from src.log_reader import read_log_file
from src.log_parser import parse_log_line, parse_log_lines
from src.log_analyzer import analyze_events
from src.hash_checker import calculate_sha256, compare_hashes

SAMPLE = (
    "Nov 03 09:00:01 server sshd[1001]: Failed password for admin "
    "from 192.168.1.10 port 5001 ssh2"
)


class TestSSHLogAnalyzer(unittest.TestCase):

    def test_log_file_reading(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text(SAMPLE + "\n", encoding="utf-8")
            self.assertEqual(len(read_log_file(path)), 1)

    def test_log_parsing(self):
        event = parse_log_line(SAMPLE)
        self.assertEqual(event["event"], "failed")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["source_ip"], "192.168.1.10")
        self.assertTrue(event["valid_ip"])

    def test_failed_login_count(self):
        events = parse_log_lines([SAMPLE])
        self.assertEqual(analyze_events(events)["failed_logins"], 1)

    def test_successful_login_count(self):
        success = SAMPLE.replace("Failed password", "Accepted password")
        events = parse_log_lines([success])
        self.assertEqual(analyze_events(events)["successful_logins"], 1)

    def test_suspicious_ip_detection(self):
        events = parse_log_lines([SAMPLE] * 4)
        result = analyze_events(events, threshold=3)
        self.assertEqual(result["suspicious_ips"]["192.168.1.10"], 4)

    def test_sha256_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text("test", encoding="utf-8")
            digest = calculate_sha256(path)
            self.assertEqual(len(digest), 64)

    def test_hash_comparison(self):
        self.assertTrue(compare_hashes("ABC123", "abc123"))
        self.assertFalse(compare_hashes("abc123", "def456"))

if __name__ == "__main__":
    unittest.main()
```

**Execute the tests:**

```bash
python -m unittest test_project -v
```
The test suite checks:
- Log file reading.
- Log parsing.
- Failed login counting.
- Successful login counting.
- Suspicious IP detection.
- SHA-256 hash generation.
- Hash comparison.

# 16. FORENSIC SIGNIFICANCE

This project demonstrates several important concepts used in digital forensic examination.

**Log Examination:** Authentication logs can provide useful information about login activity.

**Event Classification:** Failed and successful authentication events can be separated for systematic review.

**IP Address Analysis:** Repeated failed attempts from the same IP address can be flagged for further investigation.

**Hash Verification:** SHA-256 values can be used to compare file contents and support integrity verification.

**Report Generation:** Structured reports improve documentation and examination efficiency.

**Evidence Documentation:** Source file details and hash values can form part of an evidence-handling record. A formal chain of custody requires additional documented handling details.

# 17. LIMITATIONS

1. The project uses a small synthetic dataset.
2. It currently supports the specific SSH log format used in the sample.
3. The detection threshold is predefined.
4. A flagged IP address does not prove malicious activity.
5. IP addresses may be shared, spoofed, or associated with intermediary systems.
6. The project does not perform live network monitoring.
7. The generated JSON record is not a complete formal chain-of-custody document.
8. The tool is intended for educational and preliminary forensic analysis, not as a validated forensic product.

# 18. FUTURE ENHANCEMENTS

The project can be extended through:

- Support for additional SSH log formats.
- Date and time-based analysis.
- Detection of repeated login attempts across multiple accounts.
- Additional visualisation and statistical analysis.
- Automated alert generation.
- Comparison of source file hashes before and after examination.
- Improved forensic audit and evidence-handling documentation.
- Analysis of larger datasets.

# 19. CONCLUSION

The SSH Forensic Log Analyzer demonstrates the application of Python programming in digital forensic log examination.
The project successfully reads synthetic SSH authentication logs, extracts structured event information, classifies login activities, counts failed attempts, flags IP addresses exceeding a predefined threshold, calculates SHA-256 hash values, and generates multiple analysis reports.
The project also demonstrates the importance of structured evidence examination, integrity verification, and technical documentation.
Through this project, practical knowledge was developed in Python programming, log analysis, digital forensics, hashing, data processing, report generation, and software testing.

