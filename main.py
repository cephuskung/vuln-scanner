import json
from scanner.pipeline import run_full_scan
from app.report import generate_report
def main():
    target = input("Enter target IP: ").strip()
    result = run_full_scan(target)
    if result["status"] != "completed":
        print(f"\nScan failed: {result.get('error', 'unknown error')}")
        return
    results = result["results"]
    print("\nScan Results:")
    print(json.dumps(results, indent=4))
    vulnerability_details = [
        {
            "port": v.get("port"),
            "service": v.get("service"),
            "cve": v.get("cve_id"),
            "severity": v.get("severity", "Unknown"),
            "cvss_score": v.get("cvss_score"),
            "description": v.get("description", "No description available"),
            "remediation": v.get("remediation"),
        }
        for v in result["vulns"]
    ]
    counts = result["counts"]
    print("\nRisk Summary")
    print("-------------")
    for k, v in counts.items():
        print(k, ":", v)
    print("\nTotal Risk Score:", result["score"])
    generate_report(results, vulnerability_details, result["score"], counts)
if __name__ == "__main__":
    main()
