import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_DIR))

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
    