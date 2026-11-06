
import csv
import json
from pathlib import Path
import matplotlib.pyplot as plt


def generate_reports(events, analysis, source_hash, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # 1. Export parsed events to CSV
    csv_path = output_path / "parsed_events.csv"

    fieldnames = [
        "timestamp", "host", "process_id", "event",
        "username", "source_ip", "valid_ip", "raw_message"
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    # 2. Generate text summary report
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

    # 3. Generate login activity chart
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

    # 4. Generate educational chain-of-custody record
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
        "custody": str(custody_path)
    }
