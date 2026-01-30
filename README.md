# Privacy-preserving & Collaborative Dental AI

A privacy-preserving collaborative approach to dental AI research.

This repository contains the CloudFormation infrastructure setup for deploying an on-demand EC2-based annotation platform that integrates Label Studio with the Segment Anything Model 2 (SAM2) for dental image annotation tasks.

## Overview

This infrastructure enables researchers to start and stop EC2 instances on-demand via a web application, eliminating the need to run compute resources 24/7. The system is designed for cost-effective annotation workflows where you only pay for compute time when actively annotating dental images.

### Key Features

- **On-Demand EC2 Management/Cost Optimization**: Start and stop EC2 instances via web application when needed for annotation work
- **Label Studio Integration**: Full-featured annotation interface for dental images
- **SAM2 Model Integration**: Segment Anything Model 2 for AI-assisted annotation
- **Flexible Compute Options**: Support for both GPU (CUDA) and CPU configurations
- **Privacy-Preserving**: Infrastructure designed for collaborative research with privacy considerations

## EC2 Instance Specifications

### g4dn.xlarge Instance Type

- **vCPUs**: 4
- **Memory**: 16 GiB
- **GPU**: 1x NVIDIA T4 Tensor Core GPU (16 GB GPU memory)

### Device Configuration Options

The infrastructure supports two device configurations:

1. **CUDA (GPU)**: Default configuration for optimal performance
   - Uses NVIDIA T4 GPU for SAM2 model inference
   - Requires NVIDIA drivers and CUDA toolkit
   - Configured via `docker-compose-gpu.yml`

2. **CPU**: Alternative configuration for cost savings
   - Runs SAM2 model on CPU
   - Suitable for smaller workloads or testing
   - Configured via `docker-compose-cpu.yml`

