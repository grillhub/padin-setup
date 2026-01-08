#!/bin/bash
#
# CUDA Setup Script for Amazon Linux 2023
# This script installs NVIDIA drivers, CUDA toolkit, and configures Docker for GPU support
# Based on successful setup that achieved CUDA working with Tesla T4 GPU
#
# Usage: sudo ./setup_cuda.sh
#

set -e  # Exit on error

echo "=========================================="
echo "CUDA Environment Setup Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ ! -f /etc/os-release ]; then
    echo "Error: Cannot detect OS"
    exit 1
fi

source /etc/os-release
echo "Detected OS: $NAME $VERSION"
echo ""

# Check for NVIDIA GPU
echo "Step 1: Checking for NVIDIA GPU..."
if lspci | grep -i nvidia > /dev/null; then
    GPU_INFO=$(lspci | grep -i nvidia)
    echo "✓ NVIDIA GPU detected: $GPU_INFO"
else
    echo "⚠ Warning: No NVIDIA GPU detected. Continuing anyway..."
fi
echo ""

# Update system
echo "Step 2: Updating system packages..."
dnf update -y
echo "✓ System updated"
echo ""

# Install build dependencies
echo "Step 3: Installing build dependencies..."
dnf install -y kernel-devel kernel-headers gcc make dkms
echo "✓ Build dependencies installed"
echo ""

# Add NVIDIA CUDA repository for Amazon Linux 2023
echo "Step 4: Adding NVIDIA CUDA repository..."
dnf config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/amzn2023/x86_64/cuda-amzn2023.repo
dnf clean all
echo "✓ NVIDIA CUDA repository added"
echo ""

# Install NVIDIA drivers and container toolkit
echo "Step 5: Installing NVIDIA drivers and container toolkit..."
dnf install -y nvidia-driver nvidia-container-toolkit
echo "✓ NVIDIA drivers and container toolkit installed"
echo ""

# Install/upgrade NVIDIA driver using module system (open-dkms flavor)
echo "Step 6: Installing/upgrading NVIDIA driver module (open-dkms)..."
dnf -y module install nvidia-driver:open-dkms
echo "✓ NVIDIA driver module installed"
echo ""

# Install CUDA Toolkit 13.1 (latest stable)
echo "Step 7: Installing CUDA Toolkit 13.1..."
dnf -y install cuda-toolkit-13-1
echo "✓ CUDA Toolkit 13.1 installed"
echo ""

# Rebuild kernel modules for current kernel
echo "Step 8: Rebuilding NVIDIA kernel modules..."
KERNEL_VERSION=$(uname -r)
DRIVER_VERSION=$(rpm -qa | grep '^nvidia-driver-' | head -1 | sed 's/.*-\([0-9.]*\)-.*/\1/' || echo "")
if [ -n "$DRIVER_VERSION" ]; then
    dkms install nvidia/${DRIVER_VERSION} -k ${KERNEL_VERSION} || echo "⚠ Warning: DKMS install may have failed (will try to load modules anyway)"
else
    echo "⚠ Warning: Could not determine driver version for DKMS"
fi
echo "✓ Kernel modules rebuilt"
echo ""

# Load NVIDIA kernel modules
echo "Step 9: Loading NVIDIA kernel modules..."
modprobe -r nvidia_uvm nvidia_drm nvidia_modeset nvidia 2>/dev/null || true
modprobe nvidia || echo "⚠ Warning: Could not load nvidia module (may need reboot)"
modprobe nvidia_uvm || echo "⚠ Warning: Could not load nvidia_uvm module"
echo "✓ Kernel modules loaded"
echo ""

# Configure CUDA environment
echo "Step 10: Configuring CUDA environment..."
# Check which CUDA version was installed
if [ -d "/usr/local/cuda-13.1" ]; then
    CUDA_VERSION="13.1"
    CUDA_PATH="/usr/local/cuda-13.1"
elif [ -d "/usr/local/cuda-12.6" ]; then
    CUDA_VERSION="12.6"
    CUDA_PATH="/usr/local/cuda-12.6"
else
    CUDA_PATH="/usr/local/cuda"
    CUDA_VERSION="unknown"
fi

cat > /etc/profile.d/cuda.sh << EOF
export PATH=${CUDA_PATH}/bin:\$PATH
export LD_LIBRARY_PATH=${CUDA_PATH}/lib64:\$LD_LIBRARY_PATH
EOF
chmod +x /etc/profile.d/cuda.sh
source /etc/profile.d/cuda.sh
echo "✓ CUDA environment configured (CUDA ${CUDA_VERSION})"
echo ""

# Update library cache
echo "Step 11: Updating library cache..."
ldconfig
echo "✓ Library cache updated"
echo ""

# Configure Docker for NVIDIA runtime
echo "Step 12: Configuring Docker for NVIDIA runtime..."
# Configure nvidia-container-runtime
nvidia-ctk runtime configure --runtime=docker

# Update Docker daemon.json to enable BuildKit and nvidia runtime
cat > /etc/docker/daemon.json << 'EOF'
{
    "runtimes": {
        "nvidia": {
            "args": [],
            "path": "nvidia-container-runtime"
        }
    },
    "features": {
        "buildkit": true
    }
}
EOF

echo "✓ Docker configured for NVIDIA runtime"
echo ""

# Restart Docker
echo "Step 13: Restarting Docker service..."
systemctl restart docker
sleep 5
echo "✓ Docker restarted"
echo ""

# Verify installation
echo "Step 14: Verifying installation..."
echo ""

# Check NVIDIA driver
if lsmod | grep nvidia > /dev/null; then
    echo "✓ NVIDIA kernel modules loaded"
    DRIVER_VERSION=$(modinfo nvidia 2>/dev/null | grep "^version" | awk '{print $2}' || echo "Unknown")
    echo "  Driver version: $DRIVER_VERSION"
else
    echo "⚠ Warning: NVIDIA kernel modules not loaded (may need reboot)"
fi

# Check CUDA
if [ -d "$CUDA_PATH" ]; then
    echo "✓ CUDA Toolkit ${CUDA_VERSION} installed"
    if [ -f "${CUDA_PATH}/bin/nvcc" ]; then
        CUDA_VER=$(${CUDA_PATH}/bin/nvcc --version 2>/dev/null | grep "release" | sed 's/.*release \([0-9.]*\).*/\1/' || echo "Unknown")
        echo "  CUDA version: $CUDA_VER"
    fi
else
    echo "✗ CUDA Toolkit not found"
fi

# Check nvidia-container-toolkit
if command -v nvidia-container-runtime > /dev/null; then
    echo "✓ nvidia-container-runtime installed"
    RUNTIME_VERSION=$(nvidia-container-runtime --version 2>/dev/null | head -1 || echo "Unknown")
    echo "  Runtime: $RUNTIME_VERSION"
else
    echo "✗ nvidia-container-runtime not found"
fi

# Check Docker runtime
if docker info 2>/dev/null | grep -q "nvidia"; then
    echo "✓ Docker nvidia runtime configured"
else
    echo "⚠ Warning: Docker nvidia runtime not detected"
fi

# Test GPU access with a simple container
echo ""
echo "Step 15: Testing GPU access..."
echo "Testing with PyTorch container..."
if docker run --rm --gpus all pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime python -c "import torch; print('CUDA available:', torch.cuda.is_available()); print('Device count:', torch.cuda.device_count()); print('Device name:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'N/A')" 2>&1 | grep -q "CUDA available: True"; then
    echo "✓ GPU access test passed"
    DEVICE_INFO=$(docker run --rm --gpus all pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime python -c "import torch; print(torch.cuda.get_device_name(0))" 2>/dev/null || echo "N/A")
    echo "  GPU detected: $DEVICE_INFO"
else
    echo "⚠ Warning: GPU access test failed"
    echo "  This may require a system reboot to load the new driver"
    echo "  Run: sudo reboot"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. If GPU access test failed or modules weren't loaded, reboot the system:"
echo "   sudo reboot"
echo ""
echo "2. After reboot, verify GPU is accessible:"
echo "   docker run --rm --gpus all pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime python -c \"import torch; print('CUDA:', torch.cuda.is_available()); print('Device:', torch.cuda.get_device_name(0))\""
echo ""
echo "3. Navigate to your project and start the containers:"
echo "   cd /home/ec2-user/label-studio-ml-backend/label_studio_ml/examples/segment_anything_2_image"
echo "   docker-compose up -d"
echo ""
echo "4. Check if CUDA is working in the ml-backend container:"
echo "   docker-compose exec ml-backend python -c \"import torch; print('CUDA:', torch.cuda.is_available()); print('Device:', torch.cuda.get_device_name(0))\""
echo ""
echo "5. If CUDA is still False in the container, try recreating it:"
echo "   docker-compose stop ml-backend"
echo "   docker-compose rm -f ml-backend"
echo "   docker-compose up -d ml-backend"
echo ""

