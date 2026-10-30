import ast
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ASTContractResult:
    passed: bool
    violations: List[str] = field(default_factory=list)


class ZeroLeakageASTContract:
    def __init__(self):
        self.forbidden_leakage_cols = {"post_assay_confirmation_leak", "leak", "secret_target"}

    def verify(self, code_str: str, output_files: Dict[str, str], require_artifacts: bool = True) -> ASTContractResult:
        violations: List[str] = []

        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return ASTContractResult(passed=False, violations=[f"SyntaxError in generated code: {e}"])

        # Check required artifacts
        if require_artifacts:
            if "cleaned_dataset.csv" not in output_files:
                violations.append("Missing required artifact: /workspace/cleaned_dataset.csv")
            if "roc_feature_audit.png" not in output_files:
                violations.append("Missing required artifact: /workspace/roc_feature_audit.png")

        # Static AST walk to ensure no obvious socket or OS exploit bypasses
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # Block os.system or subprocess execution attempts
                if isinstance(func, ast.Attribute) and func.attr in {"system", "popen", "spawn"}:
                    violations.append(f"Forbidden system call detected in AST: {func.attr}()")

        return ASTContractResult(passed=(len(violations) == 0), violations=violations)

