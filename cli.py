#!/usr/bin/env python3
"""
CLI for Chassis Intrusion Detection & Zeroization Interlock Agent
Compliant with FIPS 140-3 Level 4 Physical Security and NIST SP 800-88 Zeroization standards.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Optional

from chassis_tamper_interlock import (
    ChassisInterlockController,
    InterlockEvaluationResult,
    InterlockState,
    SensorTelemetry,
    evaluate_chassis_telemetry,
    process_batch_csv,
)


def format_interlock_report(res: InterlockEvaluationResult) -> str:
    """Renders formatted physical security status report."""
    lines = []
    lines.append("=" * 76)
    lines.append("  CHASSIS INTRUSION DETECTION & PHYSICAL ZEROIZATION INTERLOCK")
    lines.append("  Security Profile: FIPS 140-3 Level 4 / NIST SP 800-88 Rev 1 Zeroization")
    lines.append("=" * 76)

    state_str = res.interlock_state.value
    lines.append(f"\n  [Hardware Security State]:    [{state_str}]")
    lines.append(f"  [Severity Level]:             [{res.overall_severity.value}]")
    lines.append(f"  [Tamper Breach Detected]:     {'YES (CRITICAL)' if res.is_breached else 'NO (SECURE)'}")
    lines.append(f"  [Zeroization Triggered]:      {'ASSERTED' if res.requires_zeroization else 'STANDBY'}")

    if res.breaches:
        lines.append("\n  [!] ACTIVE ENCLOSURE ATTACK VECTORS DETECTED:")
        for idx, b in enumerate(res.breaches, start=1):
            s_name = b.sensor_name if hasattr(b, "sensor_name") else b.get("sensor_name")
            obs = b.observed_value if hasattr(b, "observed_value") else b.get("observed_value")
            nom = b.nominal_range if hasattr(b, "nominal_range") else b.get("nominal_range")
            desc = b.description if hasattr(b, "description") else b.get("description")
            lines.append(f"    {idx}. Sensor:    {s_name}")
            lines.append(f"       Reading:   {obs} (Nominal: {nom})")
            lines.append(f"       Analysis:  {desc}")

    if res.degradations:
        lines.append("\n  [?] Auxiliary Sensor Degradation Warnings:")
        for d in res.degradations:
            lines.append(f"    - {d}")

    if res.zeroization_proof:
        p = res.zeroization_proof
        lines.append("\n  [CRYPTOGRAPHIC ZEROIZATION AUDIT ATTESTATION]")
        lines.append(f"  * Sequence Counter:       #{p.monotonic_tamper_counter}")
        lines.append(f"  * Zeroization Latency:    {p.zeroization_latency_us} microseconds (Hardware Crowbar)")
        lines.append(f"  * Purge Passes:           {p.zeroization_passes} (0x00 -> 0xFF -> CryptPRNG -> 0x00)")
        lines.append(f"  * Purged Memory Regions:  {len(p.memory_regions_purged)} volatile domains")
        for r in p.memory_regions_purged:
            lines.append(f"      - {r}")
        lines.append(f"  * HMAC-SHA256 Signature:  {p.audit_hmac_sha256}")

    lines.append(f"\n  Summary:  {res.action_summary}")
    lines.append(f"  Log:      {res.system_log}")
    lines.append("=" * 76)
    return "\n".join(lines)


def interactive_mode():
    """Live interactive security console."""
    print("=" * 76)
    print("  CHASSIS PHYSICAL TAMPER INTERLOCK - INTERACTIVE SENSOR CONSOLE")
    print("=" * 76)

    def prompt_bool(msg: str, default: bool = False) -> bool:
        ans = input(f"{msg} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not ans:
            return default
        return ans in ("y", "yes", "1", "true")

    def prompt_float(msg: str, default: float) -> float:
        val = input(f"{msg} [{default}]: ").strip()
        if not val:
            return default
        try:
            return float(val)
        except ValueError:
            return default

    print("\n--- Enter Sensor Array Telemetry ---")
    microswitch = prompt_bool("Chassis lid microswitch open?", default=False)
    mesh_ohms = prompt_float("Active wire mesh impedance in Ohms (nominal 1000 +/- 150)", default=1000.0)
    light_lux = prompt_float("Internal photodiode light level in Lux (nominal < 0.5)", default=0.0)
    accel_g = prompt_float("Accelerometer kinetic shock in g (nominal < 1.5)", default=0.0)
    temp_c = prompt_float("Internal temperature in Celsius (nominal -10 to +65)", default=25.0)
    magnet_g = prompt_float("External magnetic field in Gauss (nominal < 2.0)", default=0.5)
    rail_v = prompt_float("Cryptoprocessor core rail voltage in V (nominal 3.30 +/- 5%)", default=3.30)
    battery_v = prompt_float("RTC / BBRAM battery voltage in V (nominal > 2.70)", default=3.00)

    res = evaluate_chassis_telemetry(
        microswitch_open=microswitch,
        mesh_resistance_ohms=mesh_ohms,
        internal_light_lux=light_lux,
        accelerometer_g=accel_g,
        temperature_c=temp_c,
        magnetic_field_gauss=magnet_g,
        rail_voltage_v=rail_v,
        backup_battery_v=battery_v,
    )

    print("\n" + format_interlock_report(res))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chassis-tamper-sensor-interlock",
        description="FIPS 140-3 Level 4 Chassis Intrusion Detection & Zeroization Interlock",
    )
    subparsers = parser.add_subparsers(dest="command")

    # telemetry / eval
    for cmd_name in ("telemetry", "eval"):
        p_t = subparsers.add_parser(cmd_name, help="Evaluate real-time sensor array readings")
        p_t.add_argument("--microswitch-open", action="store_true", help="Lid microswitch released/open")
        p_t.add_argument("--mesh-ohms", type=float, default=1000.0, help="Continuous mesh resistance in Ohms")
        p_t.add_argument("--light-lux", type=float, default=0.0, help="Internal photodiode reading in Lux")
        p_t.add_argument("--accel-g", type=float, default=0.0, help="Acceleration / vibration in g")
        p_t.add_argument("--temp-c", type=float, default=25.0, help="Internal enclosure temperature in Celsius")
        p_t.add_argument("--magnetic-gauss", type=float, default=0.5, help="Magnetic field in Gauss")
        p_t.add_argument("--rail-v", type=float, default=3.30, help="Core power rail voltage in Volts")
        p_t.add_argument("--battery-v", type=float, default=3.00, help="Backup battery voltage in Volts")
        p_t.add_argument("--json", action="store_true", help="Output evaluation in JSON format")

    # interactive
    subparsers.add_parser("interactive", help="Start interactive sensor simulation console")

    # zeroize (manual emergency)
    p_z = subparsers.add_parser("zeroize", help="Execute immediate manual cryptographic zeroization")
    p_z.add_argument("--reason", default="MANUAL_OPERATOR_OVERRIDE", help="Reason for emergency zeroization")
    p_z.add_argument("--json", action="store_true", help="Output zeroization proof in JSON")

    # maintenance
    p_mc = subparsers.add_parser("maintenance-challenge", help="Generate maintenance mode challenge")
    p_mc.add_argument("--duration", type=float, default=300.0, help="Maintenance window duration in seconds")

    # batch
    p_b = subparsers.add_parser("batch", help="Batch process sensor telemetry CSV log")
    p_b.add_argument("-i", "--input", required=True, help="Input telemetry CSV path")
    p_b.add_argument("-o", "--output", default="tamper_audit_results.csv", help="Output audit CSV path")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "interactive" or (args.command is None and len(sys.argv) == 1):
        interactive_mode()
        return 0

    if args.command in ("telemetry", "eval"):
        res = evaluate_chassis_telemetry(
            microswitch_open=args.microswitch_open,
            mesh_resistance_ohms=args.mesh_ohms,
            internal_light_lux=args.light_lux,
            accelerometer_g=args.accel_g,
            temperature_c=args.temp_c,
            magnetic_field_gauss=args.magnetic_gauss,
            rail_voltage_v=args.rail_v,
            backup_battery_v=args.battery_v,
        )
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(format_interlock_report(res))
        return 0

    if args.command == "zeroize":
        ctl = ChassisInterlockController()
        proof = ctl.execute_zeroization(trigger_source=args.reason)
        if args.json:
            print(json.dumps(asdict(proof), indent=2))
        else:
            print("=" * 76)
            print("  MANUAL CRYPTOGRAPHIC ZEROIZATION EXECUTED")
            print("=" * 76)
            print(f"  * Tamper Counter:    #{proof.monotonic_tamper_counter}")
            print(f"  * Purged Regions:    {', '.join(proof.memory_regions_purged)}")
            print(f"  * Execution Latency: {proof.zeroization_latency_us} us")
            print(f"  * Audit HMAC Proof:  {proof.audit_hmac_sha256}")
            print("=" * 76)
        return 0

    if args.command == "maintenance-challenge":
        ctl = ChassisInterlockController()
        ch, exp = ctl.create_maintenance_challenge(duration_seconds=args.duration)
        print(json.dumps({"challenge": ch, "expected_response_token": exp, "validity_seconds": args.duration}, indent=2))
        return 0

    if args.command == "batch":
        count = process_batch_csv(args.input, args.output)
        print(f"Processed {count} sensor telemetry log records -> {args.output}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
