#!/usr/bin/env python
import argparse
import json
import os
import sys
from scanner.engine import ScannerEngine

def print_banner():
    print("=" * 70)
    print("         CIPHER - DevSecOps MCP Security Pipeline Engine")
    print("=" * 70)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="CIPHER Security Scanner")
    parser.add_argument("--mcp-file", default="target/mcp.json", help="Path to mcp.json file")
    parser.add_argument("--source-dir", default=".", help="Root directory containing codebase to scan")
    parser.add_argument("--policy", default=".CIPHER/policy.yaml", help="Path to policy.yaml configuration")
    args = parser.parse_args()

    # Verify input paths
    if not os.path.exists(args.mcp_file):
        print(f"[!] Critical Error: target file {args.mcp_file} not found.")
        sys.exit(1)

    print(f"[*] Ingestion Path  : {args.mcp_file}")
    print(f"[*] Target Directory: {os.path.abspath(args.source_dir)}")
    print(f"[*] Rules Applied   : {args.policy}")
    print("[*] Initiating 5 Checks parallel execution core...")
    print("-" * 70)

    # Initialize and execute scanner
    scanner = ScannerEngine(args.mcp_file, args.source_dir, args.policy)
    report = scanner.run_all()

    # Format output console response
    verdict = report["verdict"]
    grade = report["grade"]
    score = report["score"]
    results = report["results"]

    print("\n" + "=" * 30 + " SCAN RESULTS " + "=" * 30)
    
    for check_name, check_data in results.items():
        name_clean = check_name.replace("check", "Check ").replace("_", " ").upper()
        verdict_str = check_data["verdict"]
        badge = "🟢 PASS" if verdict_str == "PASS" else f"🔴 FAIL [{check_data['severity']}]"
        
        print(f"\n[{badge}] {name_clean}")
        print(f"  Description: {check_data['explanation']}")
        
        findings = check_data.get("findings", [])
        if findings:
            print("  Vulnerabilities Identified:")
            for item in findings:
                if "tool" in item:
                    print(f"    - Tool: {item['tool']} | Type: {item.get('type', 'EXPLOIT')} | Violation: {item.get('message', '')}")
                elif "package" in item:
                    print(f"    - Package: {item['package']} {item['version']} | CVE: {item['cve']} (CVSS: {item['cvss_score']}) | Details: {item['details'][:80]}...")
                elif "file" in item:
                    print(f"    - File: {item['file']} (Line {item['line_number']}) | Method: {item['function']} | Violation: {item['message']}")
        else:
            print("    No violations detected.")

    print("\n" + "=" * 70)
    final_badge = "🟢 PIPELINE SUCCESS" if verdict == "PASS" else ("🟡 PIPELINE WARNING" if verdict == "WARN" else "🔴 PIPELINE BLOCKED")
    print(f"  FINAL VERDICT  : {final_badge}")
    print(f"  SECURITY GRADE : {grade} (Score: {score}/100)")
    print("=" * 70)

    # Output JSON report
    report_out_path = "cipher_report.json"
    with open(report_out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Scan report written to {report_out_path}")

    # Set system exit code based on verdict
    if verdict == "BLOCK":
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
