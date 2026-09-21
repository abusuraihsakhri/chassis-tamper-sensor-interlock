"""Chassis tamper telemetry simulator.

This module evaluates simulated enclosure-sensor telemetry against configurable
thresholds. It does not control hardware, erase real cryptographic material, or
establish compliance/certification with FIPS 140-3 or NIST SP 800-88.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import math
import secrets
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class InterlockState(str, Enum):
    ARMED_SECURE = "ARMED_SECURE"
    MAINTENANCE_AUTHORIZED = "MAINTENANCE_AUTHORIZED"
    SENSOR_DEGRADED = "SENSOR_DEGRADED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    ZEROIZED_LOCKDOWN = "ZEROIZED_LOCKDOWN"


class TamperSeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    CRITICAL_BREACH = "CRITICAL_BREACH"


@dataclass
class SensorTelemetry:
    microswitch_open: bool = False
    mesh_resistance_ohms: float = 1000.0
    internal_light_lux: float = 0.0
    accelerometer_g: float = 0.0
    temperature_c: float = 25.0
    magnetic_field_gauss: float = 0.5
    rail_voltage_v: float = 3.30
    backup_battery_v: float = 3.00


@dataclass
class BreachDetail:
    sensor_name: str
    observed_value: Any
    nominal_range: str
    severity: TamperSeverity
    description: str


@dataclass
class ZeroizationProof:
    """Receipt for the simulator's zeroization event.

    The receipt records what the simulator *would* mark as purged. It is not
    proof that physical or virtual memory was erased.
    """

    zeroized_timestamp: float
    memory_regions_purged: List[str]
    zeroization_passes: int
    zeroization_latency_us: float
    monotonic_tamper_counter: int
    audit_hmac_sha256: str
    simulated: bool = True


@dataclass
class InterlockEvaluationResult:
    interlock_state: InterlockState
    overall_severity: TamperSeverity
    is_breached: bool
    requires_zeroization: bool
    breaches: List[BreachDetail] = field(default_factory=list)
    degradations: List[str] = field(default_factory=list)
    zeroization_proof: Optional[ZeroizationProof] = None
    action_summary: str = ""
    system_log: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["interlock_state"] = self.interlock_state.value
        data["overall_severity"] = self.overall_severity.value
        data["breaches"] = [
            {
                "sensor_name": breach.sensor_name,
                "observed_value": breach.observed_value,
                "nominal_range": breach.nominal_range,
                "severity": breach.severity.value,
                "description": breach.description,
            }
            for breach in self.breaches
        ]
        return data


class ChassisInterlockController:
    """Stateful controller for the telemetry and response simulation."""

    MESH_OHMS_MIN = 750.0
    MESH_OHMS_MAX = 1250.0
    LIGHT_LUX_MAX = 2.0
    ACCEL_G_MAX = 3.5
    TEMP_C_MIN = -20.0
    TEMP_C_MAX = 70.0
    MAGNET_GAUSS_MAX = 8.0
    RAIL_V_MIN = 3.00
    RAIL_V_MAX = 3.60
    BATTERY_V_MIN = 2.40

    def __init__(
        self,
        initial_state: InterlockState = InterlockState.ARMED_SECURE,
        audit_key: Optional[bytes] = None,
    ) -> None:
        self.state = initial_state
        self.monotonic_counter = 0
        self.maintenance_token: Optional[str] = None
        self.maintenance_expiry = 0.0
        self._audit_key = audit_key or secrets.token_bytes(32)

    def create_maintenance_challenge(self, duration_seconds: float = 300.0) -> Tuple[str, str]:
        """Create a simulator challenge and its response token.

        The response is intentionally returned because this is a local simulator,
        not an authentication boundary. Production systems must use an external
        authenticated maintenance mechanism and protected key material.
        """
        if not math.isfinite(duration_seconds) or duration_seconds <= 0:
            raise ValueError("duration_seconds must be a positive finite number")
        challenge = secrets.token_hex(16)
        expected_response = hmac.new(
            self._audit_key, challenge.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self.maintenance_token = expected_response
        self.maintenance_expiry = time.time() + duration_seconds
        return challenge, expected_response

    def authorize_maintenance(self, response_token: str) -> bool:
        """Validate the current simulator maintenance response token."""
        if not self.maintenance_token or time.time() > self.maintenance_expiry:
            return False
        if hmac.compare_digest(response_token.strip(), self.maintenance_token):
            self.state = InterlockState.MAINTENANCE_AUTHORIZED
            return True
        return False

    def end_maintenance(self) -> None:
        self.state = InterlockState.ARMED_SECURE
        self.maintenance_token = None
        self.maintenance_expiry = 0.0

    def execute_zeroization(self, trigger_source: str) -> ZeroizationProof:
        """Record a simulated zeroization event and return an integrity receipt."""
        start = time.perf_counter()
        self.monotonic_counter += 1
        regions = [
            "BATTERY_BACKED_RAM_BBRAM",
            "AES_256_GCM_MASTER_KEY_REGISTERS",
            "RSA_4096_PRIVATE_KEY_SRAM",
            "ECDSA_SECP384R1_SESSION_SECRETS",
            "HARDWARE_ENTROPY_SEED_STORAGE",
        ]
        latency_us = max(12.5, round((time.perf_counter() - start) * 1e6, 2))
        timestamp = time.time()
        payload = (
            f"SIMULATED_ZEROIZATION|COUNTER={self.monotonic_counter}|TS={timestamp}|"
            f"SRC={trigger_source}|REGIONS={','.join(regions)}"
        )
        digest = hmac.new(self._audit_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        self.state = InterlockState.ZEROIZED_LOCKDOWN
        return ZeroizationProof(
            zeroized_timestamp=timestamp,
            memory_regions_purged=regions,
            zeroization_passes=0,
            zeroization_latency_us=latency_us,
            monotonic_tamper_counter=self.monotonic_counter,
            audit_hmac_sha256=digest,
            simulated=True,
        )

    @staticmethod
    def _finite(value: float) -> bool:
        return math.isfinite(value)

    @staticmethod
    def _invalid_breach(sensor_name: str, value: Any, nominal_range: str) -> BreachDetail:
        return BreachDetail(
            sensor_name=sensor_name,
            observed_value=str(value),
            nominal_range=nominal_range,
            severity=TamperSeverity.CRITICAL_BREACH,
            description="Invalid or non-finite telemetry received; treated as a fail-safe breach.",
        )

    def evaluate_telemetry(self, telemetry: SensorTelemetry) -> InterlockEvaluationResult:
        breaches: List[BreachDetail] = []
        degradations: List[str] = []

        maintenance_active = self.state == InterlockState.MAINTENANCE_AUTHORIZED
        if maintenance_active and time.time() > self.maintenance_expiry:
            self.state = InterlockState.ARMED_SECURE
            maintenance_active = False
        elif maintenance_active and telemetry.microswitch_open:
            degradations.append("Lid microswitch open during the authorized simulation window.")

        if telemetry.microswitch_open and not maintenance_active:
            breaches.append(
                BreachDetail(
                    "LID_MICROSWITCH",
                    True,
                    "CLOSED (False)",
                    TamperSeverity.CRITICAL_BREACH,
                    "Chassis lid open or interlock microswitch released.",
                )
            )

        numeric_checks = [
            ("MESH_CONTINUITY_RESISTANCE", telemetry.mesh_resistance_ohms, f"{self.MESH_OHMS_MIN:.1f} - {self.MESH_OHMS_MAX:.1f} Ohm"),
            ("OPTICAL_PHOTODIODE_LUX", telemetry.internal_light_lux, f"< {self.LIGHT_LUX_MAX:.1f} Lux"),
            ("ACCELEROMETER_SHOCK", telemetry.accelerometer_g, f"< {self.ACCEL_G_MAX:.1f} g"),
            ("THERMAL_SENSOR", telemetry.temperature_c, f"{self.TEMP_C_MIN:.1f} to {self.TEMP_C_MAX:.1f} C"),
            ("MAGNETIC_HALL_EFFECT", telemetry.magnetic_field_gauss, f"< {self.MAGNET_GAUSS_MAX:.1f} Gauss"),
            ("CORE_VOLTAGE_SUPERVISOR", telemetry.rail_voltage_v, f"{self.RAIL_V_MIN:.2f} - {self.RAIL_V_MAX:.2f} V"),
            ("BACKUP_BATTERY", telemetry.backup_battery_v, f">= {self.BATTERY_V_MIN:.2f} V"),
        ]
        invalid = {name for name, value, nominal in numeric_checks if not self._finite(value)}
        for name, value, nominal in numeric_checks:
            if name in invalid:
                breaches.append(self._invalid_breach(name, value, nominal))

        if "MESH_CONTINUITY_RESISTANCE" not in invalid:
            if telemetry.mesh_resistance_ohms < self.MESH_OHMS_MIN:
                breaches.append(BreachDetail(
                    "MESH_CONTINUITY_RESISTANCE", f"{telemetry.mesh_resistance_ohms:.1f} Ohm",
                    f"{self.MESH_OHMS_MIN:.1f} - {self.MESH_OHMS_MAX:.1f} Ohm",
                    TamperSeverity.CRITICAL_BREACH,
                    "Active mesh resistance below the configured threshold.",
                ))
            elif telemetry.mesh_resistance_ohms > self.MESH_OHMS_MAX:
                breaches.append(BreachDetail(
                    "MESH_CONTINUITY_RESISTANCE", f"{telemetry.mesh_resistance_ohms:.1f} Ohm",
                    f"{self.MESH_OHMS_MIN:.1f} - {self.MESH_OHMS_MAX:.1f} Ohm",
                    TamperSeverity.CRITICAL_BREACH,
                    "Active mesh resistance above the configured threshold.",
                ))

        if "OPTICAL_PHOTODIODE_LUX" not in invalid and not maintenance_active:
            if telemetry.internal_light_lux >= self.LIGHT_LUX_MAX:
                breaches.append(BreachDetail(
                    "OPTICAL_PHOTODIODE_LUX", f"{telemetry.internal_light_lux:.2f} Lux",
                    f"< {self.LIGHT_LUX_MAX:.1f} Lux", TamperSeverity.CRITICAL_BREACH,
                    "Internal light level reached the configured breach threshold.",
                ))

        if "ACCELEROMETER_SHOCK" not in invalid and telemetry.accelerometer_g >= self.ACCEL_G_MAX:
            breaches.append(BreachDetail(
                "ACCELEROMETER_SHOCK", f"{telemetry.accelerometer_g:.2f} g",
                f"< {self.ACCEL_G_MAX:.1f} g", TamperSeverity.CRITICAL_BREACH,
                "Acceleration reached the configured breach threshold.",
            ))

        if "THERMAL_SENSOR" not in invalid:
            if telemetry.temperature_c < self.TEMP_C_MIN or telemetry.temperature_c > self.TEMP_C_MAX:
                breaches.append(BreachDetail(
                    "THERMAL_SENSOR", f"{telemetry.temperature_c:.1f} C",
                    f"{self.TEMP_C_MIN:.1f} to {self.TEMP_C_MAX:.1f} C",
                    TamperSeverity.CRITICAL_BREACH,
                    "Temperature is outside the configured enclosure range.",
                ))

        if "MAGNETIC_HALL_EFFECT" not in invalid and telemetry.magnetic_field_gauss >= self.MAGNET_GAUSS_MAX:
            breaches.append(BreachDetail(
                "MAGNETIC_HALL_EFFECT", f"{telemetry.magnetic_field_gauss:.1f} Gauss",
                f"< {self.MAGNET_GAUSS_MAX:.1f} Gauss", TamperSeverity.CRITICAL_BREACH,
                "Magnetic field reached the configured breach threshold.",
            ))

        if "CORE_VOLTAGE_SUPERVISOR" not in invalid:
            if telemetry.rail_voltage_v < self.RAIL_V_MIN or telemetry.rail_voltage_v > self.RAIL_V_MAX:
                breaches.append(BreachDetail(
                    "CORE_VOLTAGE_SUPERVISOR", f"{telemetry.rail_voltage_v:.3f} V",
                    f"{self.RAIL_V_MIN:.2f} - {self.RAIL_V_MAX:.2f} V",
                    TamperSeverity.CRITICAL_BREACH,
                    "Power rail voltage is outside the configured range.",
                ))

        if "BACKUP_BATTERY" not in invalid and telemetry.backup_battery_v < self.BATTERY_V_MIN:
            degradations.append(
                f"Backup battery voltage low: {telemetry.backup_battery_v:.2f} V "
                f"(minimum {self.BATTERY_V_MIN:.2f} V)."
            )

        if breaches:
            self.state = InterlockState.TAMPER_DETECTED
            proof = self.execute_zeroization(trigger_source=breaches[0].sensor_name)
            return InterlockEvaluationResult(
                interlock_state=self.state,
                overall_severity=TamperSeverity.CRITICAL_BREACH,
                is_breached=True,
                requires_zeroization=True,
                breaches=breaches,
                degradations=degradations,
                zeroization_proof=proof,
                action_summary=(
                    f"Tamper response simulated: {len(breaches)} breach condition(s) detected; "
                    "the model entered zeroized-lockdown state."
                ),
                system_log="[SIMULATION] Zeroization state transition recorded; no hardware memory was erased.",
            )

        if degradations:
            if self.state != InterlockState.MAINTENANCE_AUTHORIZED:
                self.state = InterlockState.SENSOR_DEGRADED
            return InterlockEvaluationResult(
                interlock_state=self.state,
                overall_severity=TamperSeverity.LOW,
                is_breached=False,
                requires_zeroization=False,
                breaches=[],
                degradations=degradations,
                action_summary=f"Sensor degradation warning: {len(degradations)} warning(s).",
                system_log="[WARNING] Simulation remains active with degraded auxiliary telemetry.",
            )

        if self.state not in (InterlockState.MAINTENANCE_AUTHORIZED, InterlockState.ZEROIZED_LOCKDOWN):
            self.state = InterlockState.ARMED_SECURE
        return InterlockEvaluationResult(
            interlock_state=self.state,
            overall_severity=TamperSeverity.NONE,
            is_breached=False,
            requires_zeroization=False,
            action_summary="All configured sensor thresholds are nominal.",
            system_log="[OK] No simulated tamper condition detected.",
        )


def evaluate_chassis_telemetry(
    microswitch_open: bool = False,
    mesh_resistance_ohms: float = 1000.0,
    internal_light_lux: float = 0.0,
    accelerometer_g: float = 0.0,
    temperature_c: float = 25.0,
    magnetic_field_gauss: float = 0.5,
    rail_voltage_v: float = 3.30,
    backup_battery_v: float = 3.00,
    controller: Optional[ChassisInterlockController] = None,
) -> InterlockEvaluationResult:
    ctl = controller or ChassisInterlockController()
    telemetry = SensorTelemetry(
        microswitch_open=bool(microswitch_open),
        mesh_resistance_ohms=float(mesh_resistance_ohms),
        internal_light_lux=float(internal_light_lux),
        accelerometer_g=float(accelerometer_g),
        temperature_c=float(temperature_c),
        magnetic_field_gauss=float(magnetic_field_gauss),
        rail_voltage_v=float(rail_voltage_v),
        backup_battery_v=float(backup_battery_v),
    )
    return ctl.evaluate_telemetry(telemetry)


def _first_present(mapping: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None and mapping[key] != "":
            return mapping[key]
    return default


def calculate_metrics(**kwargs: Any) -> Dict[str, Any]:
    """Compatibility wrapper accepting common telemetry aliases.

    A ``controller`` keyword can be supplied to preserve state across calls.
    """

    def _bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value > 0
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "open", "breach", "alarm"}
        return False

    def _float(value: Any, default: float) -> float:
        if value is None or value == "":
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return math.nan

    controller = kwargs.get("controller")
    if controller is not None and not isinstance(controller, ChassisInterlockController):
        raise TypeError("controller must be a ChassisInterlockController")

    microswitch = _bool(_first_present(kwargs, "microswitch_open", "microswitch", "lid_open", "lid", default=False))
    mesh_ohms = _float(_first_present(kwargs, "mesh_resistance_ohms", "mesh_ohms", "mesh", "primary_metric", default=1000.0), 1000.0)
    light_lux = _float(_first_present(kwargs, "internal_light_lux", "light_lux", "light", default=0.0), 0.0)
    accel_g = _float(_first_present(kwargs, "accelerometer_g", "accel_g", "acceleration", default=0.0), 0.0)
    temp_c = _float(_first_present(kwargs, "temperature_c", "temperature", "temp", default=25.0), 25.0)
    magnet_g = _float(_first_present(kwargs, "magnetic_field_gauss", "magnetic_gauss", "magnet", default=0.5), 0.5)
    rail_v = _float(_first_present(kwargs, "rail_voltage_v", "rail_voltage", "voltage", default=3.30), 3.30)
    battery_v = _float(_first_present(kwargs, "backup_battery_v", "battery_v", "battery", default=3.00), 3.00)

    return evaluate_chassis_telemetry(
        microswitch_open=microswitch,
        mesh_resistance_ohms=mesh_ohms,
        internal_light_lux=light_lux,
        accelerometer_g=accel_g,
        temperature_c=temp_c,
        magnetic_field_gauss=magnet_g,
        rail_voltage_v=rail_v,
        backup_battery_v=battery_v,
        controller=controller,
    ).to_dict()


def process_batch_csv(input_csv: str, output_csv: str) -> int:
    """Evaluate CSV telemetry rows and write a result CSV.

    One controller is reused so lockdown state and the simulator's monotonic event
    counter persist across the ordered log.
    """
    with open(input_csv, mode="r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    out_fields = list(dict.fromkeys(fieldnames + [
        "interlock_state",
        "overall_severity",
        "is_breached",
        "requires_zeroization",
        "total_breaches",
        "action_summary",
    ]))

    controller = ChassisInterlockController()
    out_rows = []
    for row in rows:
        result = calculate_metrics(controller=controller, **row)
        merged = dict(row)
        merged.update({
            "interlock_state": result["interlock_state"],
            "overall_severity": result["overall_severity"],
            "is_breached": result["is_breached"],
            "requires_zeroization": result["requires_zeroization"],
            "total_breaches": len(result.get("breaches", [])),
            "action_summary": result.get("action_summary", ""),
        })
        out_rows.append(merged)

    with open(output_csv, mode="w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=out_fields)
        writer.writeheader()
        writer.writerows(out_rows)

    return len(out_rows)
