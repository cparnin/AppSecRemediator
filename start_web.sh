#!/bin/bash
# AppSec AI Scanner - Web Interface Launcher
# Enhanced startup script with dependency checking and auto-browser launch

set -e  # Exit on any error

echo "🔒 AppSec AI Scanner - Web Interface"
echo "=================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is in use
port_in_use() {
    lsof -ti:8000 >/dev/null 2>&1
}

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command_exists python3 && ! command_exists python; then
    echo "❌ Python is not installed. Please install Python 3.8+ first."
    exit 1
fi

PYTHON_CMD="python3"
if ! command_exists python3; then
    PYTHON_CMD="python"
fi

echo "✅ Python found: $($PYTHON_CMD --version)"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found. You'll need to add your API key:"
    echo "   cp env.example .env"
    echo "   # Then edit .env to add OPENAI_API_KEY or CLAUDE_API_KEY"
    echo ""
fi

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    $PYTHON_CMD -m venv .venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment found"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source .venv/bin/activate

# Check and install dependencies
echo "📋 Checking dependencies..."

# Check if requirements are installed
if ! python -c "import flask" >/dev/null 2>&1; then
    echo "📦 Installing dependencies..."
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    pip install -r requirements-web.txt -q
    
    # Install semgrep if not present
    if ! command_exists semgrep; then
        echo "🔧 Installing Semgrep..."
        pip install semgrep -q
    fi
    
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi

# Check if port is already in use
if port_in_use; then
    echo "⚠️  Port 8000 is already in use. Stopping existing process..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Display startup information
echo ""
echo "🌐 Web Interface will be available at:"
echo "   📱 http://localhost:8000"
echo "   🌍 http://$(ipconfig getifaddr en0 2>/dev/null || hostname):8000"
echo ""
echo "✨ Features:"
echo "   📁 Repository picker with auto-discovery"
echo "   🔍 SAST, Secrets, and Dependency scanning"
echo "   🤖 AI-powered auto-remediation"
echo "   📊 Visual reports and downloads"
echo ""
echo "🎯 Usage:"
echo "   1. Open http://localhost:8000 in your browser"
echo "   2. Click 'Browse Common Locations' or enter repo path"
echo "   3. Select scan level and auto-fix options"
echo "   4. Click 'Start Security Scan'"
echo ""
echo "⏹️  Press Ctrl+C to stop the server"
echo "=================================="
echo ""

# Try to open browser automatically (macOS/Linux)
if command_exists open; then
    echo "🚀 Opening browser..."
    (sleep 3 && open http://localhost:8000) &
elif command_exists xdg-open; then
    echo "🚀 Opening browser..."
    (sleep 3 && xdg-open http://localhost:8000) &
else
    echo "💡 Manual: Open http://localhost:8000 in your browser"
fi

# Start the web server
echo "🔄 Starting web server..."
cd src && python web_app.py