import yaml
import os

class PolicyEvaluator:
    def __init__(self, policy_path):
        self.policy_path = policy_path
        self.policy_data = {}
        self.load_policy()

    def load_policy(self):
        if not os.path.exists(self.policy_path):
            print(f"[!] Policy file not found at: {self.policy_path}. Using default configuration.")
            self.policy_data = {
                "signatures": ["ignore previous instructions"],
                "capability_risk_matrix": {"dangerous_combos": [["fs_read", "net_egress"]]},
                "cve_threshold": 7.0,
                "action_mode": "block",
                "sensitive_keywords": ["delete", "write"]
            }
            return
        
        try:
            with open(self.policy_path, 'r', encoding='utf-8') as f:
                self.policy_data = yaml.safe_load(f)
            print(f"[*] Successfully loaded security policies from {self.policy_path}")
        except Exception as e:
            print(f"[!] Error reading policy YAML: {e}. Fallback used.")
            self.policy_data = {}

    def calculate_grade(self, scan_results):
        """
        Calculates an overall repository security grade from A to F.
        Deducts points for vulnerabilities based on severity.
        """
        score = 100
        for check_name, result in scan_results.items():
            if result.get("verdict") == "FAIL":
                severity = result.get("severity", "LOW")
                if isinstance(severity, str):
                    severity = severity.upper()
                else:
                    severity = str(severity).upper()
                
                if severity == "HIGH":
                    score -= 30
                elif severity == "MEDIUM":
                    score -= 15
                else:
                    score -= 5

        # Bound score to [0, 100]
        score = max(0, min(100, score))

        if score >= 90:
            return "A", score
        elif score >= 80:
            return "B", score
        elif score >= 70:
            return "C", score
        elif score >= 60:
            return "D", score
        elif score >= 50:
            return "E", score
        else:
            return "F", score

    def get_signatures(self):
        return self.policy_data.get("signatures", [])

    def get_risk_matrix(self):
        return self.policy_data.get("capability_risk_matrix", {}).get("dangerous_combos", [])

    def get_cve_threshold(self):
        return float(self.policy_data.get("cve_threshold", 7.0))

    def get_action_mode(self):
        return self.policy_data.get("action_mode", "block")

    def get_sensitive_keywords(self):
        return self.policy_data.get("sensitive_keywords", [])

    def get_hash_cache_file(self):
        return self.policy_data.get("hash_cache_file", ".cipher_cache/baseline_hashes.json")

    def evaluate_verdict(self, scan_results):
        """
        Receives findings list. Processes severity score and actions.
        Returns final verdict: PASS, WARN, or BLOCK, along with security grade and score.
        """
        action_mode = self.get_action_mode()
        verdict = "PASS"
        highest_severity = "low"
        has_block_rule = False

        for check_name, result in scan_results.items():
            if result["verdict"] == "FAIL":
                if result.get("severity") == "HIGH":
                    highest_severity = "high"
                    has_block_rule = True
                elif result.get("severity") == "MEDIUM" and highest_severity != "high":
                    highest_severity = "medium"

        if has_block_rule:
            if action_mode == "block":
                verdict = "BLOCK"
            elif action_mode == "warn" or action_mode == "audit":
                verdict = "WARN"
        elif highest_severity == "medium":
            verdict = "WARN"

        grade, score = self.calculate_grade(scan_results)

        return verdict, grade, score
