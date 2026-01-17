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
echo "Frontend Dashboard: http://localhost (or your public IP)"
echo "API Endpoint:       http://localhost/api"
echo "---------------------------------------------------"
echo "Default Admin Token: admin-token-123"
echo "Use this token to login to the dashboard and create tenants."
