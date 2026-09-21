# Chassis Tamper Sensor Interlock Simulator

### [Open the Live Application →](https://abusuraihsakhri.github.io/chassis-tamper-sensor-interlock/)

A Python simulator for evaluating chassis-tamper sensor telemetry against configurable interlock thresholds. It supports single-sample evaluation, CSV batch processing, a command-line interface, and a browser UI that runs the Python logic through Pyodide.

> **Scope:** This repository is a software simulation. It does not control physical hardware, perform real cryptographic key erasure, or establish FIPS 140-3 / NIST SP 800-88 certification or compliance.

## Features

- Evaluates lid, mesh resistance, light, acceleration, temperature, magnetic field, rail voltage, and backup-battery telemetry.
- Uses fail-safe handling for invalid or non-finite numeric input.
- Preserves interlock state across ordered CSV rows during batch processing.
- Records a simulated lockdown/zeroization response for breach conditions.
- Provides JSON and human-readable CLI output.
- Includes a compact responsive GitHub Pages interface with light and dark themes.
- Has no runtime Python package dependencies.

## Use the browser app

Open the live application above. Enter sensor values and select **Analyze telemetry**. The page loads Pyodide from a public CDN and runs the repository's Python module locally in the browser; entered telemetry is not sent to this repository.

## Command line

Python 3.9 or newer is required.

```bash
python -m pip install .
chassis-tamper-sensor-interlock eval --mesh-ohms 1000 --temp-c 25 --json
```

Other commands:

```bash
chassis-tamper-sensor-interlock interactive
chassis-tamper-sensor-interlock batch -i sample.csv -o results.csv
chassis-tamper-sensor-interlock zeroize --reason TEST_EVENT --json
```

The `zeroize` command records a **simulated** response only. It does not erase memory or keys.

## Development

```bash
python -m pip install pytest build
python -m pytest -q
python -m build
python -m pip check
```

CI tests Python 3.10, 3.11, and 3.12 and also checks package installation and the installed console command.

## Technology

- Python standard library
- `pytest` for tests
- Pyodide for browser-side Python execution
- Static HTML/CSS/JavaScript for the GitHub Pages UI
- GitHub Actions for CI and Pages deployment

## Browser compatibility

The web interface targets current versions of Chrome, Edge, Firefox, and Safari with WebAssembly and JavaScript enabled. Initial load requires network access to retrieve the Pyodide runtime.

## License

MIT. See [LICENSE](LICENSE).
