# CIPHER DevSecOps Scanner - Medium-Level Test Workspace
This workspace contains the complete, executable medium-level implementation of the **CIPHER** scanner engine and its vulnerable test target repository. It is designed to prove that the scanner detects all five checks described in the project design.
## Directory Structure
```
cipher-medium-workspace/
│
├── .CIPHER/
│   └── policy.yaml                # OPA/YAML policy definitions & signature rules
│
├── .github/
│   └── workflows/
│       └── cipher-scan.yml        # GitHub Actions CI/CD trigger workflow
│
├── scanner/                       # CIPHER Core Scanning Library
│   ├── __init__.py
│   ├── engine.py                  # Core Engine running the 5 checks in parallel
│   └── policy_evaluator.py        # OPA/Rego rule evaluation simulator
│
├── target/                        # Vulnerable target repository files
│   ├── mcp.json                   # Deliberate exploits (Poisoning, Over-privilege)
│   ├── server.py                  # Real MCP Python server (Missing auth handlers)
│   ├── package.json               # Node packages with known vulnerabilities (CVEs)
│   └── requirements.txt           # Python packages with known vulnerabilities (CVEs)
│
├── run_scan.py                    # Scanner CLI Entry Point
└── README.md
```
## Running the Security Scan
To execute the scanner locally and see it process all 5 checks against the target repository, run:
```bash
python run_scan.py
```
## How the 5 Checks Work
1. **Check 1: Tool Poisoning & Schema Analysis:** Uses signatures in `.CIPHER/policy.yaml` to detect text injection or instructions in `target/mcp.json` descriptions and schema definitions.
2. **Check 2: Authentication Check:** Inspects `target/server.py` using Python's Abstract Syntax Tree (`ast` module) to verify if sensitive methods (like `delete_user_data`) are decorated with a security wrapper (like `@auth_required`).
3. **Check 3: Over-Privilege Check:** Maps `target/mcp.json` tool capability arrays against the policy file's `dangerous_combos` matrix.
4. **Check 4: Rug Pull & Shadowing:** Hashes tool configurations using SHA-256 and compares them to `.cipher_cache/baseline_hashes.json`. Uses Levenshtein similarity metric to detect shadow/typo names.
5. **Check 5: Known CVE Check:** Parses package lists and calls the external **OSV.dev** public API to verify dependencies for vulnerabilities.
