from pathlib import Path


def read_log_file(file_path):
    """Read a log file and return non-empty lines."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        return [line.strip() for line in log_file if line.strip()]
    