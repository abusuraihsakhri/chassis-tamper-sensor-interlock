"""Compatibility exports for the chassis tamper telemetry simulator."""
from chassis_tamper_interlock import (
    BreachDetail,
    ChassisInterlockController,
    InterlockEvaluationResult,
    InterlockState,
    SensorTelemetry,
    TamperSeverity,
    ZeroizationProof,
    calculate_metrics,
    evaluate_chassis_telemetry,
    process_batch_csv,
)

__all__ = [
    "BreachDetail",
    "ChassisInterlockController",
    "InterlockEvaluationResult",
    "InterlockState",
    "SensorTelemetry",
    "TamperSeverity",
    "ZeroizationProof",
    "calculate_metrics",
    "evaluate_chassis_telemetry",
    "process_batch_csv",
]
