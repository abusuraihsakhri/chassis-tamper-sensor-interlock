"""
Unit Test Suite for Chassis Tamper Sensor Interlock Engine.
Tests multi-sensor intrusion telemetry, FIPS 140-3 physical tamper criteria,
NIST SP 800-88 cryptographic zeroization, maintenance authorization, and batch workflows.
"""

import csv
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from chassis_tamper_interlock import (
    ChassisInterlockController,
    InterlockEvaluationResult,
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
        res = evaluate_chassis_telemetry(
            microswitch_open=False,
            mesh_resistance_ohms=1000.0,
            internal_light_lux=0.0,
            accelerometer_g=0.0,
            temperature_c=25.0,
            magnetic_field_gauss=0.5,
            rail_voltage_v=3.30,
            backup_battery_v=3.00,
        )
        self.assertEqual(res.interlock_state, InterlockState.ARMED_SECURE)
        self.assertEqual(res.overall_severity, TamperSeverity.NONE)
        self.assertFalse(res.is_breached)
        self.assertFalse(res.requires_zeroization)
        self.assertIsNone(res.zeroization_proof)

    def test_lid_microswitch_tamper(self):
        res = evaluate_chassis_telemetry(microswitch_open=True)
        self.assertEqual(res.interlock_state, InterlockState.ZEROIZED_LOCKDOWN)
        self.assertEqual(res.overall_severity, TamperSeverity.CRITICAL_BREACH)
        self.assertTrue(res.is_breached)
        self.assertTrue(res.requires_zeroization)
        self.assertIsNotNone(res.zeroization_proof)
        self.assertEqual(res.breaches[0].sensor_name, "LID_MICROSWITCH")

    def test_mesh_resistance_short_circuit(self):
        # < 750 Ohms (e.g. 300 Ohms)
        res = evaluate_chassis_telemetry(mesh_resistance_ohms=300.0)
        self.assertTrue(res.is_breached)
        self.assertTrue(res.requires_zeroization)
        self.assertTrue(any(b.sensor_name == "MESH_CONTINUITY_RESISTANCE" for b in res.breaches))

    def test_mesh_resistance_open_cut(self):
        # > 1250 Ohms (e.g. 2000 Ohms)
        res = evaluate_chassis_telemetry(mesh_resistance_ohms=2000.0)
        self.assertTrue(res.is_breached)
        self.assertTrue(any(b.sensor_name == "MESH_CONTINUITY_RESISTANCE" for b in res.breaches))

    def test_mesh_resistance_nominal_boundaries(self):
        res_low = evaluate_chassis_telemetry(mesh_resistance_ohms=800.0)
        self.assertFalse(res_low.is_breached)
        res_high = evaluate_chassis_telemetry(mesh_resistance_ohms=1200.0)
        self.assertFalse(res_high.is_breached)

    def test_internal_light_breach(self):
        # >= 2.0 Lux (e.g. 15.0 Lux)
        res = evaluate_chassis_telemetry(internal_light_lux=15.0)
        self.assertTrue(res.is_breached)
        self.assertTrue(any(b.sensor_name == "OPTICAL_PHOTODIODE_LUX" for b in res.breaches))

    def test_accelerometer_drilling_tamper(self):
        # >= 3.5 g (e.g. 5.5 g)
        res = evaluate_chassis_telemetry(accelerometer_g=5.5)
        self.assertTrue(res.is_breached)
        self.assertTrue(any(b.sensor_name == "ACCELEROMETER_SHOCK" for b in res.breaches))

    def test_cryogenic_freeze_attack(self):
        # < -20 C (e.g. -35 C)
        res = evaluate_chassis_telemetry(temperature_c=-35.0)
        self.assertTrue(res.is_breached)
        self.assertTrue(any(b.sensor_name == "THERMAL_SENSOR" for b in res.breaches))

    def test_thermal_torch_attack(self):
        # > 70 C (e.g. 85 C)
        res = evaluate_chassis_telemetry(temperature_c=85.0)
        self.assertTrue(res.is_breached)
        self.assertTrue(any(b.sensor_name == "THERMAL_SENSOR" for b in res.breaches))

    def test_temperature_nominal_range(self):
        for temp in [-15.0, 0.0, 25.0, 50.0, 65.0]:
            res = evaluate_chassis_telemetry(temperature_c=temp)
            self.assertFalse(res.is_breached)

    def test_magnetic_field_attack(self):
        # >= 8.0 Gauss (e.g. 15.0 Gauss)
        res = evaluate_chassis_telemetry(magnetic_field_gauss=15.0)
        self.assertTrue(res.is_breached)
        self.assertTrue(any(b.sensor_name == "MAGNETIC_HALL_EFFECT" for b in res.breaches))

    def test_power_rail_brownout_and_glitch(self):
        # < 3.00 V (e.g. 2.70 V)
        res_brownout = evaluate_chassis_telemetry(rail_voltage_v=2.70)
        self.assertTrue(res_brownout.is_breached)

        # > 3.60 V (e.g. 3.85 V)
        res_glitch = evaluate_chassis_telemetry(rail_voltage_v=3.85)
        self.assertTrue(res_glitch.is_breached)

    def test_backup_battery_degradation_non_breach(self):
        # < 2.40 V (e.g. 2.10 V) with other sensors nominal -> SENSOR_DEGRADED, no zeroization
        res = evaluate_chassis_telemetry(backup_battery_v=2.10)
        self.assertFalse(res.is_breached)
        self.assertFalse(res.requires_zeroization)
        self.assertEqual(res.interlock_state, InterlockState.SENSOR_DEGRADED)
        self.assertTrue(len(res.degradations) > 0)

    def test_multi_sensor_simultaneous_breach(self):
        res = evaluate_chassis_telemetry(
            microswitch_open=True,
            mesh_resistance_ohms=2500.0,
            internal_light_lux=10.0,
        )
        self.assertTrue(res.is_breached)
        self.assertEqual(len(res.breaches), 3)


class TestMaintenanceAndZeroization(unittest.TestCase):
    def test_maintenance_challenge_and_authorization(self):
        ctl = ChassisInterlockController()
        ch, exp = ctl.create_maintenance_challenge(duration_seconds=60)
        self.assertTrue(ctl.authorize_maintenance(exp))
        self.assertEqual(ctl.state, InterlockState.MAINTENANCE_AUTHORIZED)

        # In maintenance authorized, opening microswitch does not breach
        telemetry = SensorTelemetry(microswitch_open=True)
        res = ctl.evaluate_telemetry(telemetry)
        self.assertFalse(res.is_breached)
        self.assertFalse(res.requires_zeroization)

        # End maintenance restores ARMED
        ctl.end_maintenance()
        self.assertEqual(ctl.state, InterlockState.ARMED_SECURE)

    def test_maintenance_invalid_token_rejected(self):
        ctl = ChassisInterlockController()
        ctl.create_maintenance_challenge(duration_seconds=60)
        self.assertFalse(ctl.authorize_maintenance("invalid_response_token"))
        self.assertEqual(ctl.state, InterlockState.ARMED_SECURE)

    def test_zeroization_proof_and_monotonic_counter(self):
        ctl = ChassisInterlockController()
        proof1 = ctl.execute_zeroization("TEST_SRC_1")
        self.assertEqual(proof1.monotonic_tamper_counter, 1)
        self.assertEqual(proof1.zeroization_passes, 4)
        self.assertTrue(len(proof1.memory_regions_purged) >= 4)
        self.assertTrue(len(proof1.audit_hmac_sha256) > 0)

        proof2 = ctl.execute_zeroization("TEST_SRC_2")
        self.assertEqual(proof2.monotonic_tamper_counter, 2)


class TestMetricsAndBatch(unittest.TestCase):
    def test_calculate_metrics_wrapper_string_inputs(self):
        row = {
            "microswitch": "open",
            "mesh_ohms": "950",
            "light": "0.1",
            "temp": "22.5",
        }
        res = calculate_metrics(**row)
        self.assertTrue(res["is_breached"])
        self.assertEqual(res["interlock_state"], "ZEROIZED_LOCKDOWN")

    def test_batch_csv_processing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = os.path.join(tmpdir, "telemetry.csv")
            out_path = os.path.join(tmpdir, "audit_out.csv")

            with open(in_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["timestamp", "microswitch_open", "mesh_resistance_ohms", "internal_light_lux", "temperature_c"],
                )
                writer.writeheader()
                writer.writerow({"timestamp": "1700000000", "microswitch_open": "0", "mesh_resistance_ohms": "1000", "internal_light_lux": "0.0", "temperature_c": "25"})
                writer.writerow({"timestamp": "1700000001", "microswitch_open": "1", "mesh_resistance_ohms": "1000", "internal_light_lux": "5.0", "temperature_c": "25"})

            count = process_batch_csv(in_path, out_path)
            self.assertEqual(count, 2)

            with open(out_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]["is_breached"], "False")
                self.assertEqual(rows[1]["is_breached"], "True")
                self.assertEqual(rows[1]["requires_zeroization"], "True")


class TestCLI(unittest.TestCase):
    def test_cli_eval_json(self):
        buf = io.StringIO()
        with patch("sys.stdout", new=buf):
            ret = cli_main(["eval", "--microswitch-open", "--json"])
            self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["is_breached"])
        self.assertEqual(data["interlock_state"], "ZEROIZED_LOCKDOWN")

    def test_cli_eval_formatted(self):
        buf = io.StringIO()
        with patch("sys.stdout", new=buf):
            ret = cli_main(["eval", "--mesh-ohms", "1000.0", "--temp-c", "25.0"])
            self.assertEqual(ret, 0)
        output = buf.getvalue()
        self.assertIn("CHASSIS INTRUSION DETECTION", output)
        self.assertIn("ARMED_SECURE", output)

    def test_cli_manual_zeroize(self):
        buf = io.StringIO()
        with patch("sys.stdout", new=buf):
            ret = cli_main(["zeroize", "--reason", "EMERGENCY_DECOMMISSION", "--json"])
            self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["monotonic_tamper_counter"], 1)

    def test_cli_maintenance_challenge(self):
        buf = io.StringIO()
        with patch("sys.stdout", new=buf):
            ret = cli_main(["maintenance-challenge", "--duration", "120"])
            self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("challenge", data)
        self.assertIn("expected_response_token", data)


if __name__ == "__main__":
    unittest.main()
