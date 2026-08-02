# Elara SecOps Custom Modules

Custom secret-hunting and hardware scanning tools built for the Elara SecOps pipeline.

## Tools

| Script | Description |
|--------|-------------|
| `hardware_scanner.py` | 10-interface hardware scanner (Serial, I2C, SPI, GPIO, USB, CAN, 1-Wire, ADC, PWM, UART) |
| `gh_secret_hunter.py` | GitHub Archive secret hunter (3-tier regex + ML + TruffleHog verification) |
| `oops_scanner.py` | Deleted commit scanner (finds force-pushed commits via .patch URLs) |
| `code_dorker.py` | GitHub code search dorker (35+ secret patterns) |
| `google_dorker.py` | Google dorking scanner (70+ queries for exposed secrets) |
| `paste_monitor.py` | Paste site monitor (crypto, telco, social media targets) |
| `ml_secret_classifier.py` | TF-IDF + Logistic Regression false-positive filter (88% F1) |
| `secret_patterns.py` | Secret regex pattern library (24+ secret types) |
| `pipeline_server.py` | Serverless pipeline orchestrator |
| `webshell.html` | Browser-based terminal for remote scan execution |

## Quick Start

### Linux / Termux
```bash
cd elara_modules
pip install pyserial smbus2 spidev python-can pyusb w1thermsensor RPi.GPIO scikit-learn requests beautifulsoup4
python3 hardware_scanner.py --all
python3 gh_secret_hunter.py --mode archive --hour 2024-01-15-12
python3 oops_scanner.py --hour 2024-01-15-12
```

### Windows PowerShell
```powershell
pip install pyserial smbus2 python-can pyusb w1thermsensor scikit-learn requests beautifulsoup4
python elara_modules\hardware_scanner.py --all
```

## Backend API

All pipelines also executable via serverless backend:
- API: https://elara-6512927d.base44.app/functions/runPipeline
- Web Shell: https://elara-6512927d.base44.app/functions/webshell

## Findings Database

All discovered secrets stored with full unredacted values, method of use, impact assessment, and disclosure targets.
