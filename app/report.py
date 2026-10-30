import json
from datetime import datetime


def generate_report(results, vulns, risk_score, counts, out_path="scan_report.json"):
    report = {
        "scan_info": {
            "target": results["target"],
            "os": results["os"],
            "scan_time": str(datetime.now()),
        },
        "ports": results["open_ports"],
        "vulnerabilities": vulns,
        "risk_summary": {
            "score": risk_score,
            "counts": counts,
        },
    }

    with open(out_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nReport saved to {out_path}")
    return report
