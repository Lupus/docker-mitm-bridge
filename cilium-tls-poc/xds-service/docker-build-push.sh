#!/bin/bash

set -e

IMAGE_NAME="ghcr.io/lupus/docker-mitm-bridge/xds-service:latest"

echo "Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

echo ""
echo "Image built successfully!"
docker images "$IMAGE_NAME"

echo ""
echo "Pushing to registry..."
docker push "$IMAGE_NAME"

echo ""
echo "✓ Build and push complete!"
echo "Image: $IMAGE_NAME"