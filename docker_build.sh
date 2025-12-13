#!/bin/bash
set -e  # Exit on any error

IMAGE_NAME='nexus.fhatt.cn/qf-gitea'
IMAGE_TAG='v1.23.5'

echo "Starting build process..."
echo "Building image: ${IMAGE_NAME}"

# Build with detailed output
if DOCKER_BUILDKIT=1 docker build --build-arg GOPROXY=https://goproxy.cn -t ${IMAGE_NAME}:${IMAGE_TAG} .; then
    echo "✅ Build successful"
    echo "📤 Pushing image to registry..."
    if docker push ${IMAGE_NAME}:${IMAGE_TAG}; then
        echo "✅ Push completed successfully"
    else
        echo "❌ Push failed"
        exit 1
    fi
else
    echo "❌ Build failed"
    exit 1
fi
