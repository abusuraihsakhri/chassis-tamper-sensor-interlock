import csv
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from chassis_tamper_interlock import (
    ChassisInterlockController,
    InterlockState,
    SensorTelemetry,
    TamperSeverity,
    calculate_metrics,
    evaluate_chassis_telemetry,
    process_batch_csv,
)
from cli import main as cli_main


class TestChassisSensorBreaches(unittest.TestCase):
    def test_nominal_enclosure_secure(self):
        result = evaluate_chassis_telemetry()
        self.assertEqual(result.interlock_state, InterlockState.ARMED_SECURE)
        self.assertEqual(result.overall_severity, TamperSeverity.NONE)
        self.assertFalse(result.is_breached)
        self.assertFalse(result.requires_zeroization)

    def test_lid_microswitch_tamper(self):
        result = evaluate_chassis_telemetry(microswitch_open=True)
        self.assertEqual(result.interlock_state, InterlockState.ZEROIZED_LOCKDOWN)
        self.assertTrue(result.is_breached)
        self.assertTrue(result.zeroization_proof.simulated)
        self.assertEqual(result.zeroization_proof.zeroization_passes, 0)

    def test_mesh_short_and_open(self):
        self.assertTrue(evaluate_chassis_telemetry(mesh_resistance_ohms=300.0).is_breached)
        self.assertTrue(evaluate_chassis_telemetry(mesh_resistance_ohms=2000.0).is_breached)

    def test_threshold_boundaries(self):
        self.assertFalse(evaluate_chassis_telemetry(mesh_resistance_ohms=750.0).is_breached)
        self.assertFalse(evaluate_chassis_telemetry(mesh_resistance_ohms=1250.0).is_breached)
        self.assertTrue(evaluate_chassis_telemetry(internal_light_lux=2.0).is_breached)
        self.assertTrue(evaluate_chassis_telemetry(accelerometer_g=3.5).is_breached)
        self.assertFalse(evaluate_chassis_telemetry(temperature_c=-20.0).is_breached)
        self.assertFalse(evaluate_chassis_telemetry(temperature_c=70.0).is_breached)
        self.assertTrue(evaluate_chassis_telemetry(magnetic_field_gauss=8.0).is_breached)
        self.assertFalse(evaluate_chassis_telemetry(rail_voltage_v=3.0).is_breached)
        self.assertFalse(evaluate_chassis_telemetry(rail_voltage_v=3.6).is_breached)

    def test_backup_battery_degradation_non_breach(self):
        result = evaluate_chassis_telemetry(backup_battery_v=2.10)
        self.assertFalse(result.is_breached)
        self.assertEqual(result.interlock_state, InterlockState.SENSOR_DEGRADED)

    def test_nonfinite_values_fail_safe(self):
        for key in (
            "mesh_resistance_ohms",
            "internal_light_lux",
            "accelerometer_g",
            "temperature_c",
            "magnetic_field_gauss",
            "rail_voltage_v",
            "backup_battery_v",
        ):
            result = evaluate_chassis_telemetry(**{key: float("nan")})
            self.assertTrue(result.is_breached, key)

    def test_zero_values_are_not_replaced_by_defaults(self):
        self.assertTrue(calculate_metrics(mesh_resistance_ohms=0)["is_breached"])
        self.assertTrue(calculate_metrics(rail_voltage_v=0)["is_breached"])
        result = calculate_metrics(backup_battery_v=0)
        self.assertFalse(result["is_breached"])
        self.assertEqual(result["interlock_state"], "SENSOR_DEGRADED")

    def test_invalid_string_fails_safe(self):
        result = calculate_metrics(rail_voltage_v="not-a-number")
        self.assertTrue(result["is_breached"])
        self.assertEqual(result["breaches"][0]["sensor_name"], "CORE_VOLTAGE_SUPERVISOR")


class TestMaintenanceAndState(unittest.TestCase):
    def test_maintenance_challenge_and_authorization(self):
        controller = ChassisInterlockController(audit_key=b"x" * 32)
        _, response = controller.create_maintenance_challenge(60)
        self.assertTrue(controller.authorize_maintenance(response))
        result = controller.evaluate_telemetry(SensorTelemetry(microswitch_open=True))
        self.assertFalse(result.is_breached)
        self.assertTrue(result.degradations)

    def test_invalid_maintenance_duration(self):
        controller = ChassisInterlockController()
        with self.assertRaises(ValueError):
            controller.create_maintenance_challenge(0)

    def test_zeroization_counter_and_lockdown_persist(self):
        controller = ChassisInterlockController(audit_key=b"y" * 32)
        first = controller.execute_zeroization("TEST")
        second = controller.execute_zeroization("TEST2")
        self.assertEqual(first.monotonic_tamper_counter, 1)
        self.assertEqual(second.monotonic_tamper_counter, 2)
        nominal = controller.evaluate_telemetry(SensorTelemetry())
        self.assertEqual(nominal.interlock_state, InterlockState.ZEROIZED_LOCKDOWN)


class TestBatchAndCLI(unittest.TestCase):
    def test_batch_csv_processing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "telemetry.csv")
            output_path = os.path.join(tmpdir, "result.csv")
            with open(input_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["rail_voltage_v"])
                writer.writeheader()
                writer.writerow({"rail_voltage_v": "3.3"})
                writer.writerow({"rail_voltage_v": "0"})
            self.assertEqual(process_batch_csv(input_path, output_path), 2)
            with open(output_path, encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["is_breached"], "False")
            self.assertEqual(rows[1]["is_breached"], "True")

    def test_empty_batch_writes_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "telemetry.csv")
            output_path = os.path.join(tmpdir, "result.csv")
            with open(input_path, "w", newline="", encoding="utf-8") as handle:
                handle.write("rail_voltage_v\n")
            self.assertEqual(process_batch_csv(input_path, output_path), 0)
            self.assertTrue(os.path.exists(output_path))

    def test_cli_eval_json(self):
        buffer = io.StringIO()
        with patch("sys.stdout", new=buffer):
            self.assertEqual(cli_main(["eval", "--rail-v", "0", "--json"]), 0)
        data = json.loads(buffer.getvalue())
        self.assertTrue(data["is_breached"])

    def test_cli_zeroize_is_explicitly_simulated(self):
        buffer = io.StringIO()
        with patch("sys.stdout", new=buffer):
            self.assertEqual(cli_main(["zeroize", "--json"]), 0)
        data = json.loads(buffer.getvalue())
        self.assertTrue(data["simulated"])
        self.assertEqual(data["zeroization_passes"], 0)

    def test_cli_no_args_explicit_empty_uses_interactive(self):
        with patch("builtins.input", side_effect=["", "", "", "", "", "", "", ""]), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(cli_main([]), 0)


if __name__ == "__main__":
    unittest.main()
