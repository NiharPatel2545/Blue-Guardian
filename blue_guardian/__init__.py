"""Blue Guardian: a guard for AI agents. Rules decide what an agent may do; a detector reads untrusted text first."""
from blue_guardian.detect import Detection, HeuristicDetector, ModelDetector
from blue_guardian.approvals import Approvals
from blue_guardian.audit import verify_log
from blue_guardian.gateway import Blocked, Guardian, run_policy_tests
from blue_guardian.policy import Decision, Policy
from blue_guardian.secret_scan import find_secrets, redact

__version__ = "0.5.0"
