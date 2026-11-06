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