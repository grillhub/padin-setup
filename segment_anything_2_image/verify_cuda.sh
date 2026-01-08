#!/bin/bash
#
# CUDA Verification Script
# Checks if CUDA environment is properly set up
#
# Usage: ./verify_cuda.sh
#

echo "=========================================="
echo "CUDA Environment Verification"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

# Check NVIDIA GPU
echo "1. Checking for NVIDIA GPU..."
if lspci | grep -i nvidia > /dev/null; then
    GPU_INFO=$(lspci | grep -i nvidia)
    echo "   ✓ GPU detected: $GPU_INFO"
else
    echo "   ✗ No NVIDIA GPU detected"
    ((ERRORS++))
fi
echo ""

# Check NVIDIA kernel modules
echo "2. Checking NVIDIA kernel modules..."
if lsmod | grep nvidia > /dev/null; then
    echo "   ✓ NVIDIA modules loaded:"
    lsmod | grep nvidia | awk '{print "     - " $1}'
    DRIVER_VERSION=$(modinfo nvidia 2>/dev/null | grep "^version" | awk '{print $2}' || echo "Unknown")
    echo "     Driver version: $DRIVER_VERSION"
else
    echo "   ✗ NVIDIA modules not loaded (may need reboot)"
    ((ERRORS++))
fi
echo ""

# Check CUDA Toolkit
echo "3. Checking CUDA Toolkit..."
if [ -d "/usr/local/cuda-12.6" ]; then
    echo "   ✓ CUDA Toolkit 12.6 installed"
    if [ -f "/usr/local/cuda-12.6/bin/nvcc" ]; then
        CUDA_VERSION=$(/usr/local/cuda-12.6/bin/nvcc --version 2>/dev/null | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/' || echo "Unknown")
        echo "     CUDA version: $CUDA_VERSION"
    fi
else
    echo "   ✗ CUDA Toolkit not found"
    ((ERRORS++))
fi
echo ""

# Check CUDA compatibility library
echo "4. Checking CUDA compatibility library..."
if [ -f "/usr/local/cuda-12.8/compat/libcuda.so.1" ]; then
    echo "   ✓ CUDA compatibility library found"
else
    echo "   ⚠ CUDA compatibility library not found"
    ((WARNINGS++))
fi
echo ""

# Check nvidia-container-runtime
echo "5. Checking nvidia-container-runtime..."
if command -v nvidia-container-runtime > /dev/null; then
    RUNTIME_VERSION=$(nvidia-container-runtime --version 2>/dev/null | head -1 || echo "Unknown")
    echo "   ✓ nvidia-container-runtime installed: $RUNTIME_VERSION"
else
    echo "   ✗ nvidia-container-runtime not found"
    ((ERRORS++))
fi
echo ""

# Check Docker configuration
echo "6. Checking Docker configuration..."
if [ -f "/etc/docker/daemon.json" ]; then
    if grep -q "nvidia" /etc/docker/daemon.json; then
        echo "   ✓ Docker nvidia runtime configured"
    else
        echo "   ✗ Docker nvidia runtime not configured"
        ((ERRORS++))
    fi
else
    echo "   ✗ Docker daemon.json not found"
    ((ERRORS++))
fi

if docker info 2>/dev/null | grep -q "nvidia"; then
    echo "   ✓ Docker recognizes nvidia runtime"
else
    echo "   ⚠ Docker doesn't show nvidia runtime (may need restart)"
    ((WARNINGS++))
fi
echo ""

# Check Docker service
echo "7. Checking Docker service..."
if systemctl is-active --quiet docker; then
    echo "   ✓ Docker service is running"
else
    echo "   ✗ Docker service is not running"
    ((ERRORS++))
fi
echo ""

# Test GPU access
echo "8. Testing GPU access in container..."
if docker run --rm --gpus all pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime python -c "import torch; exit(0 if torch.cuda.is_available() else 1)" 2>&1; then
    echo "   ✓ GPU access test passed"
    DEVICE_COUNT=$(docker run --rm --gpus all pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime python -c "import torch; print(torch.cuda.device_count())" 2>&1)
    echo "     Device count: $DEVICE_COUNT"
else
    echo "   ✗ GPU access test failed"
    ((ERRORS++))
fi
echo ""

# Check container status
echo "9. Checking ml-backend container..."
if docker ps | grep -q ml-backend; then
    echo "   ✓ ml-backend container is running"
    if docker-compose exec -T ml-backend python -c "import torch; exit(0 if torch.cuda.is_available() else 1)" 2>/dev/null; then
        echo "   ✓ CUDA available in ml-backend container"
        DEVICE_NAME=$(docker-compose exec -T ml-backend python -c "import torch; print(torch.cuda.get_device_name(0))" 2>/dev/null || echo "N/A")
        echo "     Device: $DEVICE_NAME"
    else
        echo "   ⚠ CUDA not available in ml-backend container (using CPU fallback)"
        ((WARNINGS++))
    fi
else
    echo "   ⚠ ml-backend container is not running"
    echo "     Start it with: docker-compose up -d"
    ((WARNINGS++))
fi
echo ""

# Summary
echo "=========================================="
echo "Verification Summary"
echo "=========================================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "✓ All checks passed! CUDA environment is properly configured."
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo "⚠ Some warnings found, but no critical errors."
    echo "  Warnings: $WARNINGS"
    exit 0
else
    echo "✗ Found $ERRORS error(s) and $WARNINGS warning(s)"
    echo ""
    echo "To fix issues, run:"
    echo "  sudo ./setup_cuda.sh"
    exit 1
fi

