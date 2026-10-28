import ast
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ContractAuditResult:
    passed: bool
    violations: List[str] = field(default_factory=list)


class ZeroLeakageASTContract(ast.NodeVisitor):
    """Static AST + Artifact contract verifier for M.A.R.I.A."""

    def __init__(self) -> None:
        self.split_line: int | None = None
        self.fit_calls: List[tuple[int, str]] = []
        self.violations: List[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in {"train_test_split", "StratifiedKFold"}:
            if self.split_line is None or node.lineno < self.split_line:
                self.split_line = node.lineno

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"fit", "fit_transform"}:
            call_str = ast.unparse(node) if hasattr(ast, "unparse") else node.func.attr
            self.fit_calls.append((node.lineno, call_str))

        self.generic_visit(node)

    def verify(self, source_code: str, output_files: Dict[str, str], require_artifacts: bool = True) -> ContractAuditResult:
        try:
            tree = ast.parse(source_code)
            self.visit(tree)
        except SyntaxError as e:
            return ContractAuditResult(passed=False, violations=[f"SyntaxError at line {e.lineno}: {e.msg}"])

        # 1. Check if stateful fit_transform occurred before train_test_split
        for lineno, call_str in self.fit_calls:
            if any(scaler in call_str for scaler in ["Scaler", "PCA", "Imputer"]):
                if self.split_line is not None and lineno < self.split_line:
                    self.violations.append(
                        f"AST Line {lineno}: Pre-split data leakage (`{call_str}` called before `train_test_split` at line {self.split_line})."
                    )

        # 2. Check if forbidden post-assay target leak column is used without being dropped
        if "post_assay_confirmation_leak" in source_code and "drop" not in source_code:
            self.violations.append(
                "AST Target Leak: Forbidden column `post_assay_confirmation_leak` was not dropped prior to model training."
            )

        # 3. Verify expected output artifacts were generated inside sandbox
        if require_artifacts:
            if "cleaned_dataset.csv" not in output_files:
                self.violations.append("Missing Artifact: `cleaned_dataset.csv` was not produced by the sandbox.")
            if "roc_feature_audit.png" not in output_files:
                self.violations.append("Missing Artifact: `roc_feature_audit.png` chart was not produced by the sandbox.")

        return ContractAuditResult(passed=len(self.violations) == 0, violations=self.violations)
