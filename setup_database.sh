#!/bin/bash

echo "Setting up FOSS-CHERUB CVE Database..."

# Start PostgreSQL container
echo "Starting PostgreSQL container..."
docker-compose up -d foss-cherub-db

# Wait for database to be ready
echo "Waiting for database to be ready..."
sleep 10

# Check if database is accessible
echo "Testing database connection..."
docker exec foss-cherub-db psql -U postgres -d foss_cherub -c "SELECT version();"

if [ $? -eq 0 ]; then
    echo "✅ Database is ready!"
    echo "✅ Sample CVE data has been loaded"
    echo ""
    echo "To sync with NVD API:"
    echo "1. Set your NVD API key: export NVD_API_KEY=your_api_key_here"
    echo "2. Run: python nvd_sync.py"
    echo ""
    echo "Database connection details:"
    echo "  Host: localhost"
    echo "  Port: 5432"
    echo "  Database: foss_cherub"
    echo "  User: postgres"
    echo "  Password: foss_cherub_2024"
else
    echo "❌ Database setup failed"
    exit 1
fi