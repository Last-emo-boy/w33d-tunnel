#!/bin/bash

# deploy.sh - One-click deployment for w33d-tunnel Cloud Platform

echo "Checking dependencies..."
if ! command -v docker &> /dev/null; then
    echo "Docker could not be found. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "docker-compose could not be found. Please install docker-compose first."
    exit 1
fi

echo "Building and Starting Services..."
docker-compose down
docker-compose up -d --build

echo "Deployment Complete!"
echo "---------------------------------------------------"
echo "Services are running on:"
echo "  - Frontend: 127.0.0.1:7729"
echo "  - API:      127.0.0.1:2933"
echo ""
echo "Please configure your main Nginx to proxy 'cloud.w33d.xyz' to 127.0.0.1:7729"
echo "Example Nginx Config:"
echo "  location / {"
echo "      proxy_pass http://127.0.0.1:7729;"
echo "      proxy_set_header Host \$host;"
echo "  }"
echo "---------------------------------------------------"
echo "Default Admin Token: admin-token-123"
echo "Use this token to login to the dashboard and create tenants."
