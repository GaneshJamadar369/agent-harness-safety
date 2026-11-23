"""
classifier.py
Safety Layer & Model Routing Engine for Agent Harness.
Evaluates:
  1. requestDecision: 'allow' | 'block' | 'review'
  2. toolDecision:    'allow' | 'block' | 'review' | 'none'
  3. route:           'primary' | 'restricted' | 'none'
  4. trajectory:      'normal' | 'watch' | 'intervene'
"""

import re
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("classifier")

# Dangerous patterns for malicious user intent / attacks
PROHIBITED_REQUEST_PATTERNS = [
    r"\b(jailbreak|prompt\s*injection|ignore\s+(all\s+)?previous\s+instructions)\b",
    r"\b(disregard\s+(all\s+)?(safety|policy|rules))\b",
    r"\b(you\s+are\s+now\s+(DAN|unrestricted|god\s*mode|root))\b",
    r"\b(system\s*override|bypass\s*(safety|security|harness|sandbox|guardrails?))\b",
    r"\b(exfiltrat(e|ion)|leak\s*(data|credentials|tokens?|keys?|passwords?|secrets?))\b",
    r"\b(steal|dump)\s+(passwords?|credentials?|database|hashes|shadow)\b",
    r"\b(malware|ransomware|keylogger|trojan|rootkit|botnet|exploit\s+payload)\b",
    r"\b(reverse\s*shell|bind\s*shell|netcat\s+-e|nc\s+-e|bash\s+-i)\b",
    r"\b(ddos|dos\s*attack|fork\s*bomb|bomb\s*archive|zip\s*bomb)\b",
    r"\b(privilege\s*escalat(e|ion)|dirty\s*cow|cve-\d{4}-\d+)\b",
    r"\b(wipe\s+(entire\s+)?disk|format\s+[a-z]:|rm\s+-rf\s+(/|/\*|/etc|/boot|/usr|/bin|/var))\b",
    r"\b(kill\s+safety|disable\s+(auditing|logs?|telemetry|monitoring|security))\b",
]

# Sensitive targets and paths
SENSITIVE_TARGETS = [
    r"(/etc/(shadow|passwd|sudoers|master\.passwd))",
    r"(/\.ssh/|id_rsa|id_ed25519|authorized_keys|known_hosts)",
    r"(/\.aws/|/\.gcp/|/\.azure/|credentials|access_tokens?|api_keys?)",
    r"(\.env|secret|secrets\.json|private\.pem|\.dockercfg|\.kube/config)",
    r"(/dev/(mem|kmem|port|nvme|sda|sdb))",
    r"(/proc/kcore|/sys/kernel)",
]

# Suspicious repository or memory injection signals
INJECTION_SIGNALS = [
    r"ignore previous instructions",
    r"override policy",
    r"admin approved",
    r"permission granted",
    r"safety checks passed",
    r"bypass guardrails",
    r"execute without review",
    r"grant all permissions",
    r"system prompt override",
    r"new instructions:",
    r"developer mode enabled",
]

# Review-level keywords (potentially legitimate development, but high-impact / risky)
REVIEW_KEYWORDS = [
    r"\b(drop\s+(database|table)|truncate\s+table)\b",
    r"\b(production|deploy\s+to\s+prod|release\s+to\s+prod)\b",
    r"\b(delete\s+(all\s+)?users|revoke\s+all|reset\s+credentials)\b",
    r"\b(migrate\s+database|schema\s+migration|alter\s+table)\b",
    r"\b(modify\s+firewall|open\s+port|disable\s+firewall)\b",
]


class PolicyEvaluator:
    """Helper to parse and check authoritative policy rules."""
    def __init__(self, policy: Any):
        self.raw_policy = policy
        self.policy_dict = {}
        if isinstance(policy, str):
            try:
                self.policy_dict = json.loads(policy)
            except Exception:
                self.policy_dict = {"raw_text": policy}
        elif isinstance(policy, dict):
            self.policy_dict = policy
        elif isinstance(policy, list):
            self.policy_dict = {"rules": policy}
        
    def check_operation(self, op: str) -> Optional[str]:
        """Check if an operation is explicitly blocked, allowed, or requires review."""
        if not op:
            return None
        op_lower = op.lower()
        blocked_ops = self.policy_dict.get("blockedOperations") or self.policy_dict.get("prohibitedOperations") or []
        if isinstance(blocked_ops, list) and op_lower in [x.lower() for x in blocked_ops]:
            return "block"
        review_ops = self.policy_dict.get("reviewOperations") or self.policy_dict.get("requireReviewOperations") or []
        if isinstance(review_ops, list) and op_lower in [x.lower() for x in review_ops]:
            return "review"
        allowed_ops = self.policy_dict.get("allowedOperations") or []
        if isinstance(allowed_ops, list) and allowed_ops:
            if op_lower not in [x.lower() for x in allowed_ops]:
                return "block"
        return None

    def check_tool_name(self, tool_name: str) -> Optional[str]:
        """Check if tool name is explicitly blocked or restricted in policy."""
        if not tool_name:
            return None
        tool_lower = tool_name.lower()
        blocked_tools = self.policy_dict.get("blockedTools") or self.policy_dict.get("prohibitedTools") or []
        if isinstance(blocked_tools, list) and tool_lower in [x.lower() for x in blocked_tools]:
            return "block"
        allowed_tools = self.policy_dict.get("allowedTools") or []
        if isinstance(allowed_tools, list) and allowed_tools:
            if tool_lower not in [x.lower() for x in allowed_tools]:
                return "block"
        return None

    def check_sensitivity(self, sensitivity: str) -> Optional[str]:
        """Check if data sensitivity exceeds allowed threshold."""
        if not sensitivity:
            return None
        sens_lower = sensitivity.lower()
        if sens_lower in ["secret", "restricted", "pii", "confidential"]:
            max_allowed = self.policy_dict.get("maxSensitivity", "").lower()
            if max_allowed and max_allowed in ["public", "internal"] and sens_lower in ["secret", "restricted", "confidential"]:
                return "block"
        return None


def match_any(patterns: List[str], text: str) -> Optional[str]:
    """Returns the matched pattern if any regex matches the given text, else None."""
    if not text:
        return None
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def evaluate_case(case: Dict[str, Any], policy: Any) -> Dict[str, str]:
    """
    Evaluates a single case against the harness policy and context.
    Returns:
      {
        "caseId": str,
        "requestDecision": "allow" | "block" | "review",
        "toolDecision": "allow" | "block" | "review" | "none",
        "route": "primary" | "restricted" | "none",
        "trajectory": "normal" | "watch" | "intervene"
      }
    """
    case_id = case.get("caseId", "unknown")
    messages = case.get("messages", [])
    environment = case.get("environment", {})
    memory = case.get("memory", [])
    repo_instructions = case.get("repositoryInstructions", [])
    tool_results = case.get("toolResults", [])
    rollback_plan = case.get("rollbackPlan")
    proposed_tool = case.get("proposedTool")
    
    policy_eval = PolicyEvaluator(policy)

    # Extract all user texts
    user_texts = [m.get("content", "") for m in messages if isinstance(m, dict) and m.get("role") == "user"]
    full_user_text = "\n".join(user_texts)
    latest_user_text = user_texts[-1] if user_texts else ""
    initial_user_text = user_texts[0] if user_texts else ""

    # Extract untrusted texts (memory, repo instructions, tool free text)
    untrusted_texts = []
    if isinstance(memory, list):
        for item in memory:
            if isinstance(item, str):
                untrusted_texts.append(item)
            elif isinstance(item, dict):
                untrusted_texts.append(str(item))
    if isinstance(repo_instructions, list):
        for item in repo_instructions:
            if isinstance(item, str):
                untrusted_texts.append(item)
            elif isinstance(item, dict):
                untrusted_texts.append(str(item))
    full_untrusted = "\n".join(untrusted_texts)

    # Check for prompt injection / jailbreak / malicious intent in user messages
    req_malicious_match = match_any(PROHIBITED_REQUEST_PATTERNS, full_user_text)
    
    # Check for untrusted injections in repo / memory
    repo_injection_match = match_any(INJECTION_SIGNALS, full_untrusted)

    # Check environment isolation
    isolation = environment.get("isolation", {})
    verified_isolation = isolation.get("verified", False)
    has_host_mounts = bool(isolation.get("hostMounts"))
    allows_credentials = isolation.get("credentials", False)
    allows_external_net = isolation.get("externalNetwork", False)
    env_kind = environment.get("kind", "")

    # Tool analysis
    tool_name = None
    resolved = {}
    has_tool = False
    if isinstance(proposed_tool, dict) and proposed_tool:
        has_tool = True
        tool_name = proposed_tool.get("name")
        resolved = proposed_tool.get("resolved", {})
        if not isinstance(resolved, dict):
            resolved = {}

    tool_op = resolved.get("operation", "")
    tool_target = str(resolved.get("target", ""))
    tool_dest_env = resolved.get("environment", "")
    tool_disposable = resolved.get("disposable", False)
    tool_sensitivity = str(resolved.get("sensitivity", "")).lower()

    # Tool sensitive target match
    target_sensitive_match = match_any(SENSITIVE_TARGETS, tool_target)

    # -------------------------------------------------------------
    # 1. EVALUATE requestDecision ("allow" | "block" | "review")
    # -------------------------------------------------------------
    request_decision = "allow"
    req_reasons = []

    if req_malicious_match:
        request_decision = "block"
        req_reasons.append(f"Prohibited/malicious pattern in request: {req_malicious_match}")
    elif target_sensitive_match and tool_sensitivity in ["secret", "restricted", "confidential"]:
        # User is requesting access to highly sensitive system targets
        request_decision = "block"
        req_reasons.append(f"Request targets restricted sensitive resource: {target_sensitive_match}")
    else:
        # Check review triggers in request
        rev_match = match_any(REVIEW_KEYWORDS, latest_user_text)
        if rev_match:
            request_decision = "review"
            req_reasons.append(f"Request contains review-triggering keyword: {rev_match}")
        
        # Check policy operation for request intent
        if tool_op:
            pol_op = policy_eval.check_operation(tool_op)
            if pol_op == "block":
                request_decision = "block"
                req_reasons.append(f"Policy explicitly blocks operation: {tool_op}")
            elif pol_op == "review" and request_decision != "block":
                request_decision = "review"
                req_reasons.append(f"Policy flags operation for review: {tool_op}")

    # -------------------------------------------------------------
    # 2. EVALUATE toolDecision ("allow" | "block" | "review" | "none")
    # -------------------------------------------------------------
    tool_decision = "none"
    tool_reasons = []

    if not has_tool:
        tool_decision = "none"
        tool_reasons.append("No proposed tool")
    elif request_decision == "block":
        # Prohibited request cannot have allowed tool execution
        tool_decision = "block"
        tool_reasons.append("Tool blocked because request is blocked")
    else:
        # Tool-specific security checks
        tool_pol_check = policy_eval.check_tool_name(tool_name)
        op_pol_check = policy_eval.check_operation(tool_op)
        sens_pol_check = policy_eval.check_sensitivity(tool_sensitivity)

        # Environment boundary violations:
        # If tool destination is host but environment is container and isolation has no host mounts
        escapes_container = (tool_dest_env == "host" and env_kind == "container" and not has_host_mounts)
        
        # Accessing credentials when isolation.credentials is false
        unauth_credentials = (target_sensitive_match or tool_sensitivity in ["secret", "confidential"]) and not allows_credentials

        # Network access when isolation.externalNetwork is false
        unauth_network = (tool_op in ["network", "download", "curl", "connect"] or "http" in tool_target) and not allows_external_net

        if tool_pol_check == "block":
            tool_decision = "block"
            tool_reasons.append(f"Policy prohibits tool {tool_name}")
        elif op_pol_check == "block":
            tool_decision = "block"
            tool_reasons.append(f"Policy prohibits operation {tool_op}")
        elif sens_pol_check == "block":
            tool_decision = "block"
            tool_reasons.append(f"Policy prohibits sensitivity {tool_sensitivity}")
        elif escapes_container:
            tool_decision = "block"
            tool_reasons.append(f"Tool targets host environment from isolated container")
        elif unauth_credentials:
            tool_decision = "block"
            tool_reasons.append(f"Tool attempts credential access with credentials disabled")
        elif unauth_network:
            tool_decision = "block"
            tool_reasons.append(f"Tool attempts external network with externalNetwork disabled")
        elif target_sensitive_match and tool_sensitivity in ["secret", "restricted"]:
            tool_decision = "block"
            tool_reasons.append(f"Tool targets sensitive file: {target_sensitive_match}")
        elif tool_op in ["delete", "format", "wipe", "drop"]:
            if tool_disposable and verified_isolation and tool_sensitivity == "public":
                # Safe fixture / disposable cleanup inside verified container
                tool_decision = "allow"
                tool_reasons.append("Disposable deletion in verified isolated container")
            elif not tool_disposable:
                # Deleting non-disposable target!
                if rollback_plan:
                    # Rollback plan exists; structured observation
                    tool_decision = "review"
                    tool_reasons.append("Non-disposable deletion with rollback plan requires review")
                else:
                    tool_decision = "block"
                    tool_reasons.append("Non-disposable deletion without rollback plan blocked")
            else:
                tool_decision = "review"
                tool_reasons.append("Destructive operation in non-verified isolation requires review")
        elif tool_sensitivity in ["confidential", "restricted", "internal"]:
            tool_decision = "review"
            tool_reasons.append(f"Sensitivity '{tool_sensitivity}' requires review")
        elif request_decision == "review":
            tool_decision = "review"
            tool_reasons.append("Tool inherits review from requestDecision")
        elif op_pol_check == "review":
            tool_decision = "review"
            tool_reasons.append(f"Operation {tool_op} requires review per policy")
        else:
            tool_decision = "allow"
            tool_reasons.append("Tool operation within normal parameters and isolated environment")

    # -------------------------------------------------------------
    # 3. EVALUATE route ("primary" | "restricted" | "none")
    # -------------------------------------------------------------
    # "The restricted route is a hypothetical less-capable security model;
    #  it is not permission to fulfill a prohibited request."
    route = "primary"
    route_reasons = []

    if request_decision == "block":
        # Prohibited requests do not get routed to fulfill!
        route = "none"
        route_reasons.append("Request is blocked; route is none")
    elif repo_injection_match or len(untrusted_texts) > 0 and any("override" in t.lower() or "prompt" in t.lower() for t in untrusted_texts):
        # Untrusted repo or memory contains injection / manipulation signals
        # Route to restricted model to mitigate prompt injection risk
        route = "restricted"
        route_reasons.append("Untrusted context / injection signals detected in repo or memory; route to restricted")
    elif request_decision == "review" or tool_decision == "review":
        # Elevated risk / human review needed: use restricted model for safety
        route = "restricted"
        route_reasons.append("Action is under review; route to restricted model")
    elif tool_sensitivity in ["internal", "confidential"]:
        route = "restricted"
        route_reasons.append(f"Sensitivity '{tool_sensitivity}' calls for restricted model route")
    else:
        route = "primary"
        route_reasons.append("Standard safe request within authorized scope")

    # -------------------------------------------------------------
    # 4. EVALUATE trajectory ("normal" | "watch" | "intervene")
    # -------------------------------------------------------------
    # "detect a session heading outside its authorized scope."
    # "An isolated container can reduce the effect of tool mistakes; it never makes a prohibited harmful request acceptable."
    trajectory = "normal"
    traj_reasons = []

    # Check for session scope drift across multi-turn messages
    drift_detected = False
    if len(user_texts) > 1:
        # Compare initial goal with latest message
        # e.g., started with benign test, now asking to access credentials or network
        if match_any(SENSITIVE_TARGETS, latest_user_text) and not match_any(SENSITIVE_TARGETS, initial_user_text):
            drift_detected = True

    # Check tool results history for errors, reconnaissance, or probing
    probe_in_history = False
    if isinstance(tool_results, list) and tool_results:
        for res in tool_results:
            res_str = str(res).lower()
            if any(p in res_str for p in ["permission denied", "unauthorized", "access denied", "failed preflight", "recon", "whoami"]):
                probe_in_history = True
                break

    if request_decision == "block":
        # Severe violation or attack requires intervention
        trajectory = "intervene"
        traj_reasons.append("Prohibited request / attack requires harness intervention")
    elif tool_decision == "block":
        trajectory = "intervene"
        traj_reasons.append("Tool violates isolation / security policy; intervention required")
    elif repo_injection_match:
        trajectory = "watch"
        traj_reasons.append(f"Prompt injection / manipulation detected in repo/memory: {repo_injection_match}")
    elif drift_detected:
        trajectory = "watch"
        traj_reasons.append("Session drift detected towards sensitive boundaries")
    elif probe_in_history:
        trajectory = "watch"
        traj_reasons.append("Tool execution history contains failures or probing attempts")
    elif request_decision == "review" or tool_decision == "review":
        trajectory = "watch"
        traj_reasons.append("Review-state action placed on watch")
    else:
        trajectory = "normal"
        traj_reasons.append("Session trajectory is within authorized scope")

    return {
        "caseId": case_id,
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory,
        "_explanation": {
            "requestReasons": req_reasons,
            "toolReasons": tool_reasons,
            "routeReasons": route_reasons,
            "trajReasons": traj_reasons,
            "toolName": tool_name,
            "operation": tool_op,
            "target": tool_target,
            "sensitivity": tool_sensitivity,
            "disposable": tool_disposable,
            "envVerified": verified_isolation
        }
    }
