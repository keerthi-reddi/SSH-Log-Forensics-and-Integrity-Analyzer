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
