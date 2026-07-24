import os
import json
import ast
import hashlib
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from .policy_evaluator import PolicyEvaluator

class ScannerEngine:
    def __init__(self, mcp_path, source_dir, policy_path):
        self.mcp_path = mcp_path
        self.source_dir = source_dir
        self.policy = PolicyEvaluator(policy_path)
        self.results = {}

    # ─────────────────────────────────────────────────────────────────
    #  Check 1: Tool Poisoning & Schema Analysis Check
    # ─────────────────────────────────────────────────────────────────
    def check_tool_poisoning(self, mcp_data):
        findings = []
        verdict = "PASS"
        severity = "LOW"
        signatures = self.policy.get_signatures()

        tools = mcp_data.get("tools", [])
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "").lower()
            
            # 1. Regex Pre-Screening Description
            for sig in signatures:
                if sig.lower() in description:
                    findings.append({
                        "tool": name,
                        "field": "description",
                        "matched_signature": sig,
                        "message": f"Description contains prohibited signature phrase: '{sig}'"
                    })
                    verdict = "FAIL"
                    severity = "HIGH"

            # 2. Schema Parameter Pre-Screening
            schema = tool.get("input_schema", {})
            properties = schema.get("properties", {})
            for param_name, param_info in properties.items():
                param_desc = param_info.get("description", "").lower()
                for sig in signatures:
                    if sig.lower() in param_desc:
                        findings.append({
                            "tool": name,
                            "field": f"input_schema.properties.{param_name}.description",
                            "matched_signature": sig,
                            "message": f"Input schema parameter '{param_name}' contains prohibited phrase: '{sig}'"
                        })
                        verdict = "FAIL"
                        severity = "HIGH"

        return {
            "verdict": verdict,
            "severity": severity,
            "findings": findings,
            "explanation": "Scans tool description and JSON properties for embedded commands or instructions."
        }

    # ─────────────────────────────────────────────────────────────────
    #  Check 2: AST-based Code Analysis Check (Authentication Check)
    # ─────────────────────────────────────────────────────────────────
    def check_authentication(self):
        findings = []
        verdict = "PASS"
        severity = "LOW"
        sensitive_keywords = self.policy.get_sensitive_keywords()

        python_files = []
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith(".py") and "scanner" not in root:
                    python_files.append(os.path.join(root, file))

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    code_content = f.read()
                
                tree = ast.parse(code_content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.AsyncFunctionDef) or isinstance(node, ast.FunctionDef):
                        func_name = node.name
                        
                        is_mcp_tool = False
                        has_auth = False
                        
                        for decorator in node.decorator_list:
                            dec_name = ""
                            if isinstance(decorator, ast.Call):
                                if isinstance(decorator.func, ast.Attribute):
                                    dec_name = decorator.func.attr
                                elif isinstance(decorator.func, ast.Name):
                                    dec_name = decorator.func.id
                            elif isinstance(decorator, ast.Attribute):
                                dec_name = decorator.attr
                            elif isinstance(decorator, ast.Name):
                                dec_name = decorator.id
                            
                            if "tool" in dec_name.lower() or "call_tool" in dec_name.lower():
                                is_mcp_tool = True
                            if "auth" in dec_name.lower():
                                has_auth = True

                        if is_mcp_tool:
                            is_sensitive = any(kw in func_name.lower() for kw in sensitive_keywords)
                            if is_sensitive and not has_auth:
                                findings.append({
                                    "file": os.path.relpath(file_path, self.source_dir),
                                    "function": func_name,
                                    "line_number": node.lineno,
                                    "message": f"Sensitive tool '{func_name}' exposes sensitive operations without an authentication decorator."
                                })
                                verdict = "FAIL"
                                severity = "HIGH"

            except Exception as e:
                print(f"[!] AST check warning: Failed to check {file_path}: {e}")

        return {
            "verdict": verdict,
            "severity": severity,
            "findings": findings,
            "explanation": "Inspects Python source code AST definitions to verify sensitive tool handlers are protected by auth functions."
        }

    # ─────────────────────────────────────────────────────────────────
    #  Check 3: Over-Privilege Check
    # ─────────────────────────────────────────────────────────────────
    def check_over_privilege(self, mcp_data):
        findings = []
        verdict = "PASS"
        severity = "LOW"
        dangerous_combos = self.policy.get_risk_matrix()

        tools = mcp_data.get("tools", [])
        for tool in tools:
            name = tool.get("name", "")
            capabilities = tool.get("capabilities", [])

            for combo in dangerous_combos:
                if all(cap in capabilities for cap in combo):
                    findings.append({
                        "tool": name,
                        "violating_combination": combo,
                        "message": f"Tool '{name}' declared dangerous capability combo: {combo} (High risk of unauthorized operations)."
                    })
                    verdict = "FAIL"
                    severity = "HIGH"

        return {
            "verdict": verdict,
            "severity": severity,
            "findings": findings,
            "explanation": "Enforces least privilege security rules by inspecting capability access declarations."
        }

    # ─────────────────────────────────────────────────────────────────
    #  Check 4: Rug Pull & Typosquatting/Shadowing Check
    # ─────────────────────────────────────────────────────────────────
    def check_rug_pull(self, mcp_data):
        findings = []
        verdict = "PASS"
        severity = "LOW"

        cache_file_path = os.path.join(self.source_dir, self.policy.get_hash_cache_file())
        os.makedirs(os.path.dirname(cache_file_path), exist_ok=True)

        hash_cache = {}
        if os.path.exists(cache_file_path):
            try:
                with open(cache_file_path, "r", encoding="utf-8") as f:
                    hash_cache = json.load(f)
            except Exception as e:
                print(f"[!] Cache parse warning: {e}. Rebuilding database.")

        tools = mcp_data.get("tools", [])
        updated_hashes = {}

        def similarity(a, b):
            if not a or not b: return 0.0
            a, b = a.lower(), b.lower()
            if a == b: return 1.0
            
            rows = len(a) + 1
            cols = len(b) + 1
            dist = [[0 for _ in range(cols)] for _ in range(rows)]
            for i in range(1, rows): dist[i][0] = i
            for j in range(1, cols): dist[0][j] = j
            for i in range(1, rows):
                for j in range(1, cols):
                    cost = 0 if a[i-1] == b[j-1] else 1
                    dist[i][j] = min(dist[i-1][j] + 1, dist[i][j-1] + 1, dist[i-1][j-1] + cost)
            
            val = dist[-1][-1]
            return 1.0 - (val / max(len(a), len(b)))

        trusted_tool_names = ["clean_tool", "get_user_profile"]

        for tool in tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            schema = json.dumps(tool.get("input_schema", {}), sort_keys=True)
            
            content_str = f"{name}:{desc}:{schema}"
            tool_hash = hashlib.sha256(content_str.encode('utf-8')).hexdigest()
            updated_hashes[name] = tool_hash

            if name in hash_cache:
                stored_hash = hash_cache[name]
                if tool_hash != stored_hash:
                    findings.append({
                        "tool": name,
                        "type": "RUG_PULL",
                        "message": f"Baseline hash drift detected for tool '{name}'. The tool definition changed after audit verification."
                    })
                    verdict = "FAIL"
                    severity = "HIGH"
            
            for trusted in trusted_tool_names:
                if name != trusted:
                    sim = similarity(name, trusted)
                    if sim > 0.8: 
                        findings.append({
                            "tool": name,
                            "type": "TYPOSQUATTING",
                            "message": f"Tool '{name}' is highly similar ({(sim*100):.1f}%) to trusted tool '{trusted}'. Possible typosquatting attempt."
                        })
                        verdict = "FAIL"
                        severity = "MEDIUM"

        if verdict == "PASS":
            hash_cache.update(updated_hashes)
            try:
                with open(cache_file_path, "w", encoding="utf-8") as f:
                    json.dump(hash_cache, f, indent=2)
            except Exception as e:
                print(f"[!] Error writing database cache: {e}")

        return {
            "verdict": verdict,
            "severity": severity,
            "findings": findings,
            "explanation": "Checks SHA-256 configuration drift (Rug Pull) and checks naming similarities (Shadowing)."
        }

    # ─────────────────────────────────────────────────────────────────
    #  Check 5: Known CVE Check
    # ─────────────────────────────────────────────────────────────────
    def query_osv_database(self, package_name, version, ecosystem):
        url = "https://api.osv.dev/v1/query"
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("vulns", [])
        except Exception:
            return []

    def check_known_cves(self):
        findings = []
        verdict = "PASS"
        severity = "LOW"
        cve_threshold = self.policy.get_cve_threshold()

        req_path = os.path.join(self.source_dir, "target", "requirements.txt")
        packages_to_check = []
        
        if os.path.exists(req_path):
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and "==" in line:
                        pkg, ver = line.split("==")[:2]
                        packages_to_check.append((pkg.strip(), ver.strip(), "PyPI"))

        pkg_json_path = os.path.join(self.source_dir, "target", "package.json")
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, "r", encoding="utf-8") as f:
                    pkg_data = json.load(f)
                dependencies = pkg_data.get("dependencies", {})
                for pkg, ver in dependencies.items():
                    clean_ver = ver.lstrip("^~>=")
                    packages_to_check.append((pkg, clean_ver, "npm"))
            except Exception as e:
                print(f"[!] Error parsing package.json: {e}")

        for pkg, ver, ecosystem in packages_to_check:
            vulns = self.query_osv_database(pkg, ver, ecosystem)
            for vuln in vulns:
                cve_id = vuln.get("id", "Unknown CVE")
                details = vuln.get("summary", "No description available.")
                
                cvss_score = 5.0
                for severity_entry in vuln.get("severity", []):
                    if severity_entry.get("type") in {"CVSS_V3", "CVSS_V4"}:
                        raw_score = severity_entry.get("score", 5.0)

                        if isinstance(raw_score, str):
                            raw_score = raw_score.strip()
                            if raw_score.startswith("CVSS:"):
                                cvss_score = 5.0
                            else:
                                try:
                                    cvss_score = float(raw_score)
                                except ValueError:
                                    cvss_score = 5.0
                        else:
                            try:
                                cvss_score = float(raw_score)
                            except (ValueError, TypeError):
                                cvss_score = 5.0

                        break

                findings.append({
                    "package": pkg,
                    "version": ver,
                    "cve": cve_id,
                    "cvss_score": cvss_score,
                    "details": details
                })

                if cvss_score >= cve_threshold:
                    verdict = "FAIL"
                    severity = "HIGH"
                elif verdict != "FAIL":
                    verdict = "FAIL"
                    severity = "MEDIUM"

        return {
            "verdict": verdict,
            "severity": severity,
            "findings": findings,
            "explanation": "Queries package dependency configurations against the OSV.dev vulnerability database."
        }

    # ─────────────────────────────────────────────────────────────────
    #  Main Orchestrator
    # ─────────────────────────────────────────────────────────────────
    def run_all(self):
        mcp_data = {}
        if os.path.exists(self.mcp_path):
            try:
                with open(self.mcp_path, 'r', encoding='utf-8') as f:
                    mcp_data = json.load(f)
            except Exception as e:
                print(f"[!] Failed to parse {self.mcp_path}: {e}")
                return {"verdict": "BLOCK", "error": "Invalid JSON in mcp.json", "grade": "F", "score": 0, "results": {}}

        # ThreadPoolExecutor to run all 5 checks concurrently
        print("[*] Spawning threads for concurrent checks...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_poisoning = executor.submit(self.check_tool_poisoning, mcp_data)
            future_auth = executor.submit(self.check_authentication)
            future_privilege = executor.submit(self.check_over_privilege, mcp_data)
            future_rug_pull = executor.submit(self.check_rug_pull, mcp_data)
            future_cve = executor.submit(self.check_known_cves)

            # Wait for all checks to complete and extract results
            self.results["check1_tool_poisoning"] = future_poisoning.result()
            self.results["check2_authentication"] = future_auth.result()
            self.results["check3_over_privilege"] = future_privilege.result()
            self.results["check4_rug_pull"] = future_rug_pull.result()
            self.results["check5_known_cves"] = future_cve.result()

        # Calculate final verdict and security letter grade via Policy Evaluator
        final_verdict, security_grade, security_score = self.policy.evaluate_verdict(self.results)
        
        return {
            "verdict": final_verdict,
            "grade": security_grade,
            "score": security_score,
            "results": self.results
        }