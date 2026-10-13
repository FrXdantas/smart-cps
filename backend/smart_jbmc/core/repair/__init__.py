"""Reparo de bugs: heurístico (baseline) e guiado por LLM (verificado).

A validação é sempre feita pela fase de regressão (re-verificação com o BMC):
nenhum patch conta como reparado sem o verificador provar SAFE.
"""

from .heuristic import build_fixed_source, fixed_source
from .loop import RepairResult, repair_run, repair_target
from .regression import RegressionResult, regression_check

__all__ = [
    "fixed_source", "build_fixed_source",
    "regression_check", "RegressionResult",
    "repair_target", "repair_run", "RepairResult",
]
