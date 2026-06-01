#!/usr/bin/env bash
# setup_sift.sh - Automated ProofSIFT Deployment for SANS Judges
set -e

echo "========================================================================"
echo "            PROOFSIFT — Automated SIFT Workstation Setup"
echo "========================================================================"
echo ""

# 1. Detect environment
echo "[1/5] Checking environment..."
PYTHON_VERSION=$(python3 --version 2>/dev/null || echo "none")
if [ "$PYTHON_VERSION" = "none" ]; then
    echo "  ERROR: Python 3 is not installed. Install it with:"
    echo "    sudo apt-get install -y python3 python3-pip python3-venv"
    exit 1
fi
echo "  Detected: $PYTHON_VERSION"

# 2. Update system dependencies
echo "[2/5] Installing system dependencies..."
sudo apt-get update -y -qq
sudo apt-get install -y -qq python3-pip python3-venv sqlite3 >/dev/null 2>&1
echo "  System dependencies: OK"

# 3. Establish isolated Python environment
echo "[3/5] Creating isolated Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "  Virtual environment: activated"

# 4. Install ProofSIFT in editable mode
echo "[4/5] Installing ProofSIFT package..."
python3 -m pip install --upgrade pip -q
python3 -m pip install -e . -q
echo "  Package installed: OK"

# 5. Validate submission assets
echo "[5/5] Running submission validation..."
proofsift validate-submission --root . 2>&1
echo ""

echo "========================================================================"
echo "  DEPLOYMENT COMPLETE"
echo "========================================================================"
echo ""
echo "  Run the demo case:"
echo "    proofsift run --case cases/demo_case/case.json --max-iterations 3"
echo ""
echo "  Run the benchmark:"
echo "    proofsift benchmark --case cases/demo_case/case.json \\"
echo "      --ground-truth cases/demo_case/ground_truth.json"
echo ""
