#!/bin/bash
# Elara SecOps — Secret Hunter Setup Script
# Run: bash setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Elara SecOps — Secret Hunter Setup${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[FAIL]${NC} Python 3 not found. Install python3 first."
    exit 1
fi

PYVER=$(python3 --version 2>&1)
echo -e "${GREEN}[OK]${NC} $PYVER"

# Install Python dependencies
echo -e "${YELLOW}[*]${NC} Installing Python dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt" -q 2>&1 | tail -5
echo -e "${GREEN}[OK]${NC} Dependencies installed"

# Create output directories
mkdir -p "$SCRIPT_DIR/output/findings"
mkdir -p "$SCRIPT_DIR/output/logs"
mkdir -p "$SCRIPT_DIR/output/reports"
echo -e "${GREEN}[OK]${NC} Output directories created"

# Set GitHub token from env or prompt
if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${YELLOW}[!]${NC} GITHUB_TOKEN not set."
    echo -e "    Set it with: export GITHUB_TOKEN=ghp_your_token_here"
    echo -e "    Without it, GitHub API calls will be rate-limited to 60/hr."
fi

# Verify key scripts exist
echo ""
echo -e "${YELLOW}[*]${NC} Verifying installation..."
for f in scanners/gh_secret_hunter.py scanners/google_dorker.py scanners/paste_monitor.py scanners/code_dorker.py scanners/oops_scanner.py config/secret_patterns.py; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        echo -e "${GREEN}[OK]${NC} $f"
    else
        echo -e "${RED}[MISSING]${NC} $f"
    fi
done

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Setup Complete!${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo "Quick start:"
echo "  python3 scanners/gh_secret_hunter.py --range 6          # Scan last 6 hours of GH Archive"
echo "  python3 scanners/google_dorker.py --github              # GitHub code search dorking"
echo "  python3 scanners/paste_monitor.py --continuous          # Monitor paste sites"
echo "  python3 scanners/code_dorker.py --dorks all             # GitHub code dorking"
echo "  python3 scanners/oops_scanner.py --range 24             # Scan deleted commits"
echo "  python3 dashboard/pipeline_server.py                   # Start local dashboard"
echo ""
echo "  bash termux/termux_cybersec_install.sh                  # Termux (Android) setup"
