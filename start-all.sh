#!/bin/bash

# FOSS-CHERUB Complete Startup Script
# This script starts both the backend API and frontend simultaneously

# Removed set -e to prevent script from exiting on Docker errors

echo "=========================================="
echo "FOSS-CHERUB Application Startup"
echo "=========================================="
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Start PostgreSQL database directly
echo "[1/5] Starting PostgreSQL database..."
if command -v docker &> /dev/null; then
    # Start PostgreSQL container directly
    docker run -d --name foss-cherub-db \
        -e POSTGRES_DB=foss_cherub \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=foss_cherub_2024 \
        -p 5432:5432 \
        postgres:15 2>/dev/null || echo "Database container already running or failed to start"
    echo "Waiting for database to be ready..."
    sleep 10
else
    echo "Docker not found. Using mock CVE data..."
fi

# Kill any existing processes
echo "[2/5] Cleaning up existing processes..."
pkill -f "backend.api:app" 2>/dev/null || true
pkill -f "next dev" 2>/dev/null || true
sleep 2

# Clean up Next.js lock file if it exists
echo "[3/5] Cleaning up Next.js cache..."
rm -rf foss-cherub-ui/.next/dev/lock 2>/dev/null || true

# Start Backend API
echo "[4/5] Starting Backend API on port 8082..."
cd "$SCRIPT_DIR/backend" && python api.py > /tmp/backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# Wait for backend to start
sleep 10

# Start Frontend
echo "[5/5] Starting Frontend on port 3002..."
cd "$SCRIPT_DIR/foss-cherub-ui"
PORT=3002 npm run dev > /tmp/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

echo ""
echo "=========================================="
echo "✓ FOSS-CHERUB is running!"
echo "=========================================="
echo ""
echo "Frontend: http://localhost:3002"
echo "Backend:  http://localhost:8082"
echo "Database: PostgreSQL on port 5432"
echo ""
echo "Backend logs:  tail -f /tmp/backend.log"
echo "Frontend logs: tail -f /tmp/frontend.log"
echo "Database logs: docker logs foss-cherub-db"
echo ""
echo "To stop the application, run:"
echo "  kill $BACKEND_PID $FRONTEND_PID"
if command -v docker &> /dev/null; then
    echo "  docker stop foss-cherub-db && docker rm foss-cherub-db"
fi
echo ""
echo "Press Ctrl+C to exit (this won't stop the services)"
echo "=========================================="

# Wait for both processes
wait
