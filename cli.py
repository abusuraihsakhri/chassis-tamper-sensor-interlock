#!/usr/bin/env python3
"""Command-line interface for the chassis tamper telemetry simulator."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from chassis_tamper_interlock import (
    ChassisInterlockController,
    InterlockEvaluationResult,
    evaluate_chassis_telemetry,
    process_batch_csv,
)


def format_interlock_report(result: InterlockEvaluationResult) -> str:
    lines = [
        "=" * 72,
        "  CHASSIS TAMPER TELEMETRY SIMULATOR",
        "  Threshold evaluation only — no hardware control or real memory erasure",
        "=" * 72,
        f"\n  State:                 {result.interlock_state.value}",
        f"  Severity:              {result.overall_severity.value}",
        f"  Breach detected:       {'YES' if result.is_breached else 'NO'}",
        f"  Zeroization response:  {'SIMULATED' if result.requires_zeroization else 'NOT TRIGGERED'}",
    ]
    if result.breaches:
        lines.append("\n  Breaches:")
        for index, breach in enumerate(result.breaches, start=1):
            lines.extend([
                f"    {index}. {breach.sensor_name}",
                f"       Reading: {breach.observed_value} (expected {breach.nominal_range})",
                f"       Detail:  {breach.description}",
            ])
    if result.degradations:
        lines.append("\n  Warnings:")
        lines.extend(f"    - {warning}" for warning in result.degradations)
    if result.zeroization_proof:
        proof = result.zeroization_proof
        lines.extend([
            "\n  Simulated response receipt:",
            f"    Event counter: {proof.monotonic_tamper_counter}",
            f"    Simulated:     {proof.simulated}",
            f"    Receipt HMAC:  {proof.audit_hmac_sha256}",
        ])
    lines.extend([f"\n  Summary: {result.action_summary}", "=" * 72])
    return "\n".join(lines)


def interactive_mode() -> None:
    def prompt_bool(message: str, default: bool = False) -> bool:
        answer = input(f"{message} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not answer:
            return default
        return answer in {"y", "yes", "1", "true"}

    def prompt_float(message: str, default: float) -> float:
        value = input(f"{message} [{default}]: ").strip()
        if not value:
            return default
        try:
            return float(value)
        except ValueError:
            print("Invalid number; using default.", file=sys.stderr)
            return default

    result = evaluate_chassis_telemetry(
        microswitch_open=prompt_bool("Chassis lid microswitch open?"),
        mesh_resistance_ohms=prompt_float("Mesh resistance (Ohm)", 1000.0),
        internal_light_lux=prompt_float("Internal light (lux)", 0.0),
        accelerometer_g=prompt_float("Acceleration / vibration (g)", 0.0),
        temperature_c=prompt_float("Temperature (C)", 25.0),
        magnetic_field_gauss=prompt_float("Magnetic field (Gauss)", 0.5),
        rail_voltage_v=prompt_float("Core rail voltage (V)", 3.30),
        backup_battery_v=prompt_float("Backup battery voltage (V)", 3.00),
    )
    print(format_interlock_report(result))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chassis-tamper-sensor-interlock",
        description="Evaluate simulated chassis tamper sensor telemetry.",
    )
    subparsers = parser.add_subparsers(dest="command")

    for command in ("telemetry", "eval"):
        telemetry = subparsers.add_parser(command, help="Evaluate one telemetry sample")
        telemetry.add_argument("--microswitch-open", action="store_true")
        telemetry.add_argument("--mesh-ohms", type=float, default=1000.0)
        telemetry.add_argument("--light-lux", type=float, default=0.0)
        telemetry.add_argument("--accel-g", type=float, default=0.0)
        telemetry.add_argument("--temp-c", type=float, default=25.0)
        telemetry.add_argument("--magnetic-gauss", type=float, default=0.5)
        telemetry.add_argument("--rail-v", type=float, default=3.30)
        telemetry.add_argument("--battery-v", type=float, default=3.00)
        telemetry.add_argument("--json", action="store_true")

    subparsers.add_parser("interactive", help="Prompt for one telemetry sample")

    zeroize = subparsers.add_parser("zeroize", help="Record a simulated zeroization response")
    zeroize.add_argument("--reason", default="MANUAL_SIMULATION")
    zeroize.add_argument("--json", action="store_true")

    maintenance = subparsers.add_parser("maintenance-challenge", help="Create a simulator maintenance challenge")
    maintenance.add_argument("--duration", type=float, default=300.0)

    batch = subparsers.add_parser("batch", help="Evaluate a telemetry CSV")
    batch.add_argument("-i", "--input", required=True)
    batch.add_argument("-o", "--output", default="tamper_audit_results.csv")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "interactive" or (args.command is None and (argv is None or len(argv) == 0)):
        interactive_mode()
        return 0

    if args.command in {"telemetry", "eval"}:
        result = evaluate_chassis_telemetry(
            microswitch_open=args.microswitch_open,
            mesh_resistance_ohms=args.mesh_ohms,
            internal_light_lux=args.light_lux,
            accelerometer_g=args.accel_g,
            temperature_c=args.temp_c,
            magnetic_field_gauss=args.magnetic_gauss,
            rail_voltage_v=args.rail_v,
            backup_battery_v=args.battery_v,
        )
        print(json.dumps(result.to_dict(), indent=2) if args.json else format_interlock_report(result))
        return 0

    if args.command == "zeroize":
        controller = ChassisInterlockController()
        proof = controller.execute_zeroization(args.reason)
        if args.json:
            print(json.dumps(asdict(proof), indent=2))
        else:
            print("Simulated zeroization response recorded; no hardware memory was erased.")
            print(f"Event counter: {proof.monotonic_tamper_counter}")
            print(f"Receipt HMAC: {proof.audit_hmac_sha256}")
        return 0

    if args.command == "maintenance-challenge":
        controller = ChassisInterlockController()
        challenge, response = controller.create_maintenance_challenge(args.duration)
        print(json.dumps({
            "challenge": challenge,
            "demo_response_token": response,
            "validity_seconds": args.duration,
            "simulation_only": True,
        }, indent=2))
        return 0

    if args.command == "batch":
        count = process_batch_csv(args.input, args.output)
        print(f"Processed {count} telemetry row(s) -> {args.output}")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
