# Chassis Tamper Sensor Interlock & Cryptographic Zeroization Engine

> **Domain:** Hardware Security, Cryptographic Module Protection & Critical Infrastructure  
> **Security Standards:** FIPS 140-3 Physical Security Level 4, NIST SP 800-88 Rev 1 (Guidelines for Media Sanitization), ISO/IEC 19790

---

## 📖 System Overview

The **Chassis Tamper Sensor Interlock** is a high-assurance physical security engine implementing FIPS 140-3 Level 4 envelope protection for cryptographic hardware modules (HSMs, secure enclaves, medical diagnostic units). It continuously monitors a multi-modal physical sensor array and executes deterministic finite state machine (FSM) transitions, triggering autonomous cryptographic zeroization when physical breach envelopes are crossed.

### Monitored Physical Sensor Array

| Sensor Channel | Nominal Envelope | Breach Condition | Attack Vector Mitigated |
|:---|:---|:---|:---|
| **Microswitch Interlock** | `Closed` (0) | `Open` (1) | Physical lid/cover removal |
| **Conductive Mesh Barrier** | $800\,\Omega \le R \le 1200\,\Omega$ | $R < 500\,\Omega \lor R > 1500\,\Omega$ | Drill-through, micro-probing, cutting |
| **Internal Ambient Photodiode**| $< 0.5\text{ lux}$ | $\ge 2.0\text{ lux}$ | Light intrusion via chassis aperture |
| **3-Axis Accelerometer** | $< 1.5\text{ g}$ | $\ge 4.0\text{ g}$ | Ballistic attack, physical extraction |
| **Thermal Envelope** | $-20^\circ\text{C} \le T \le +70^\circ\text{C}$ | $T < -30^\circ\text{C} \lor T > +85^\circ\text{C}$ | Cryogenic attack, thermal probing |
| **Hall-Effect Magnetometer** | $< 5.0\text{ Gauss}$ | $\ge 20.0\text{ Gauss}$ | Magnetic sensor spoofing / reed defeat |
| **Power Rail & Battery** | $V_{rail} \ge 3.0\text{V}, V_{bat} \ge 2.5\text{V}$ | $V_{rail} < 2.7\text{V} \land V_{bat} < 2.2\text{V}$ | Brownout / power-glitching attack |

---

## 💻 CLI Quickstart & Usage

### 1. Evaluate Sensor Array Telemetry
```bash
python cli.py telemetry --microswitch 0 --mesh 1000.0 --light 0.0 --accel 0.1 --temp 25.0 --battery 3.0
```

### 2. Interactive Sensor Simulation Console
```bash
python cli.py interactive
```

### 3. Immediate Cryptographic Zeroization Command
```bash
python cli.py zeroize
```

### 4. Batch Process Sensor Telemetry CSV Log
```bash
python cli.py batch -i sample.csv -o out_results.csv
```

---

## 🧪 Verification & Testing

Execute comprehensive unit and FSM integrity tests:
```bash
python -m pytest -p no:zarr
```
