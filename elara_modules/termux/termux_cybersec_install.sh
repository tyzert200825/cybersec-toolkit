#!/data/data/com.termux/files/usr/bin/bash
# Cybersec Toolkit Installer for Termux (Android aarch64)
# Run: bash termux_cybersec_install.sh

set -e

echo "============================================"
echo "  Cybersec Toolkit Installer for Termux"
echo "============================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# 1. Update Termux packages
echo ">>> Updating Termux packages..."
pkg update -y 2>/dev/null && pkg upgrade -y 2>/dev/null
ok "Packages updated"

# 2. Install core dependencies
echo ">>> Installing core dependencies..."
pkg install -y golang git python python-pip clang make libandroid-glob termux-tools curl wget jq openssh 2>/dev/null
ok "Core dependencies installed"

# 3. Set up Go paths
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
ok "Go paths configured"

# 4. Install Go-based security tools
echo ">>> Installing Go security tools..."

echo "  - Nuclei (vuln scanner)..."
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null
ok "nuclei installed"

echo "  - Subfinder (subdomain enum)..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
ok "subfinder installed"

echo "  - httpx (HTTP prober)..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
ok "httpx installed"

echo "  - Naabu (port scanner)..."
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null
ok "naabu installed"

echo "  - Katana (web crawler)..."
go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null
ok "katana installed"

echo "  - DNSx (DNS toolkit)..."
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null
ok "dnsx installed"

echo "  - TLSx (TLS scanner)..."
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest 2>/dev/null
ok "tlsx installed"

echo "  - Uncover (exposed hosts)..."
go install github.com/projectdiscovery/uncover/cmd/uncover@latest 2>/dev/null
ok "uncover installed"

echo "  - Assetfinder (subdomain finder)..."
go install github.com/tomnomnom/assetfinder@latest 2>/dev/null
ok "assetfinder installed"

echo "  - Waybackurls (Wayback Machine)..."
go install github.com/tomnomnom/waybackurls@latest 2>/dev/null
ok "waybackurls installed"

echo "  - GAU (GetAllUrls)..."
go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null
ok "gau installed"

echo "  - Gobuster (dir brute force)..."
go install github.com/OJ/gobuster/v3@latest 2>/dev/null
ok "gobuster installed"

echo "  - Ffuf (fuzzer)..."
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null
ok "ffuf installed"

echo "  - Hakrawler (crawler)..."
go install github.com/hakluke/hakrawler@latest 2>/dev/null
ok "hakrawler installed"

# 5. Download Nuclei templates
echo ">>> Downloading Nuclei templates..."
$GOPATH/bin/nuclei -update-templates 2>/dev/null
ok "nuclei templates downloaded"

# 6. Install Python security tools
echo ">>> Installing Python security tools..."
pip install shodan arjun dnspython requests paramiko PyJWT cryptography 2>/dev/null
ok "Python tools installed"

# 7. Install SQLMap
echo ">>> Installing SQLMap..."
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $HOME/sqlmap 2>/dev/null
ln -sf $HOME/sqlmap/sqlmap.py $PREFIX/bin/sqlmap 2>/dev/null
ok "sqlmap installed"

# 8. Install Nikto
echo ">>> Installing Nikto..."
git clone --depth 1 https://github.com/sullo/nikto.git $HOME/nikto 2>/dev/null
ln -sf $HOME/nikto/program/nikto.pl $PREFIX/bin/nikto 2>/dev/null
ok "nikto installed"

# 9. Install TruffleHog
echo ">>> Installing TruffleHog..."
ARCH=$(uname -m)
TH_VERSION="3.96.0"
TH_URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VERSION}/trufflehog_${TH_VERSION}_linux_arm64.tar.gz"
curl -fsSL "$TH_URL" -o /tmp/trufflehog.tar.gz 2>/dev/null
if [ -s /tmp/trufflehog.tar.gz ]; then
  cd /tmp && tar xzf trufflehog.tar.gz 2>/dev/null
  mv trufflehog $PREFIX/bin/ 2>/dev/null
  chmod +x $PREFIX/bin/trufflehog 2>/dev/null
  rm -f /tmp/trufflehog.tar.gz
  ok "trufflehog installed"
else
  # Try building from source as fallback
  echo "  Binary download failed, building from source..."
  go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null
  ok "trufflehog built from source"
fi

# 10. Install Nmap (Termux version)
echo ">>> Installing Nmap..."
pkg install -y nmap 2>/dev/null && ok "nmap installed" || warn "nmap may need manual install: pkg install nmap"

# 11. Start SSH server for remote access
echo ">>> Setting up SSH server..."
sshd 2>/dev/null && ok "SSH server started on port 8022" || warn "SSH already running or needs manual start: sshd"

# 12. Verify installations
echo ""
echo "============================================"
echo "  Installation Verification"
echo "============================================"
echo ""

export PATH=$PATH:$HOME/go/bin:$PREFIX/bin

PASS=0
FAIL=0
TOTAL=0

verify() {
  TOTAL=$((TOTAL+1))
  if command -v "$1" >/dev/null 2>&1; then
    ok "$1: $(command -v $1)"
    PASS=$((PASS+1))
  else
    fail "$1: NOT FOUND"
    FAIL=$((FAIL+1))
  fi
}

verify nuclei
verify subfinder
verify httpx
verify naabu
verify katana
verify dnsx
verify tlsx
verify uncover
verify assetfinder
verify waybackurls
verify gau
verify gobuster
verify ffuf
verify hakrawler
verify trufflehog
verify nmap
verify sqlmap
verify nikto
verify shodan
verify arjun
verify jq

echo ""
echo "============================================"
echo "  RESULTS: $PASS/$TOTAL tools installed"
echo "============================================"

if [ $FAIL -gt 0 ]; then
  echo ""
  echo "Failed tools: $FAIL"
  echo "Some tools may need a retry or manual install."
fi

echo ""
echo "Nuclei templates: $(find $HOME/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l) templates"
echo ""
echo "SSH server running on port 8022"
echo "Tailscale IP: $(tailscale ip -4 2>/dev/null || echo 'check tailscale status')"
echo ""
echo "Done! Your Termux cybersec toolkit is ready."
echo ""
echo "To start SSH server manually: sshd"
echo "To verify tools: nuclei -version, subfinder -version, etc."
