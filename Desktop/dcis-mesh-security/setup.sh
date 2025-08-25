#!/bin/bash
# setup.sh - Linux/Mac/Raspberry Pi Setup Script

echo "================================================"
echo "DCIS Mesh Security System - Quick Setup"
echo "================================================"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "raspbian" ]]; then
            OS="raspberrypi"
        fi
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Function to install packages
install_packages() {
    echo "Installing required packages..."
    
    if [ "$OS" == "raspberrypi" ]; then
        sudo apt update
        sudo apt install -y python3-pip python3-venv mosquitto mosquitto-clients
        
        # Configure Mosquitto
        echo "Configuring MQTT broker..."
        sudo tee /etc/mosquitto/conf.d/dcis.conf > /dev/null <<EOF
listener 1883 0.0.0.0
allow_anonymous true
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
EOF
        
        sudo systemctl restart mosquitto
        sudo systemctl enable mosquitto
        
    elif [ "$OS" == "linux" ]; then
        sudo apt update
        sudo apt install -y python3-pip python3-venv
        
    elif [ "$OS" == "mac" ]; then
        # Check for Homebrew
        if ! command -v brew &> /dev/null; then
            echo "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        brew install python3 mosquitto
        brew services start mosquitto
    fi
}

# Function to setup Python environment
setup_python() {
    echo "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv venv
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    echo "Installing Python packages..."
    pip install paho-mqtt==1.6.1
    pip install psutil==5.9.5
    pip install netifaces==0.11.0
    
    # Install GUI packages (skip on Raspberry Pi lite)
    if [ "$OS" != "raspberrypi" ]; then
        pip install customtkinter==5.2.0
        pip install matplotlib==3.7.1
    fi
    
    echo "Python environment setup complete!"
}

# Function to test MQTT
test_mqtt() {
    echo "Testing MQTT connection..."
    
    if [ "$OS" == "raspberrypi" ]; then
        BROKER="localhost"
    else
        read -p "Enter MQTT broker IP (e.g., 192.168.0.221): " BROKER
    fi
    
    # Test MQTT
    timeout 2 mosquitto_sub -h $BROKER -t test/topic &
    PID=$!
    sleep 1
    mosquitto_pub -h $BROKER -t test/topic -m "Test successful"
    wait $PID
    
    if [ $? -eq 0 ]; then
        echo "✓ MQTT test successful!"
    else
        echo "✗ MQTT test failed. Please check broker configuration."
    fi
}

# Function to create directory structure
create_structure() {
    echo "Creating project structure..."
    
    mkdir -p results
    mkdir -p logs
    mkdir -p config
    
    echo "✓ Directory structure created"
}

# Main installation flow
main() {
    echo ""
    echo "This script will install and configure the DCIS Mesh Security System"
    echo ""
    read -p "Continue with installation? (y/n): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled"
        exit 1
    fi
    
    # Install packages
    install_packages
    
    # Setup Python
    setup_python
    
    # Create structure
    create_structure
    
    # Test MQTT
    test_mqtt
    
    echo ""
    echo "================================================"
    echo "Installation Complete!"
    echo "================================================"
    echo ""
    echo "Next steps:"
    
    if [ "$OS" == "raspberrypi" ]; then
        echo "1. Start the edge coordinator:"
        echo "   python3 coordinator.py --id pi_coordinator --broker localhost --pi-mode"
        echo ""
        echo "2. Start virtual nodes:"
        echo "   python3 virtual_node.py --broker localhost --pi-mode --count 3"
    else
        echo "1. Activate virtual environment:"
        echo "   source venv/bin/activate"
        echo ""
        echo "2. Start the coordinator:"
        echo "   python coordinator.py --broker <MQTT_IP>"
        echo ""
        echo "3. Start the attack simulator:"
        echo "   python attack_simulator.py --broker <MQTT_IP>"
        echo ""
        echo "4. Start the dashboard:"
        echo "   python dashboard.py --broker <MQTT_IP>"
    fi
    
    echo ""
    echo "For automated demo, run:"
    echo "   python demo_run.py --broker <MQTT_IP>"
    echo ""
}

# Run main function
main

# ================================================
# Windows Setup Script - setup.bat
# ================================================
: '
@echo off
echo ================================================
echo DCIS Mesh Security System - Windows Setup
echo ================================================

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Please install Python 3.11+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Creating virtual environment...
python -m venv venv

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing required packages...
pip install paho-mqtt==1.6.1
pip install psutil==5.9.5
pip install netifaces==0.11.0
pip install customtkinter==5.2.0
pip install matplotlib==3.7.1

echo Creating directory structure...
if not exist results mkdir results
if not exist logs mkdir logs
if not exist config mkdir config

echo.
echo ================================================
echo Installation Complete!
echo ================================================
echo.
echo Next steps:
echo 1. Activate virtual environment:
echo    venv\Scripts\activate
echo.
echo 2. Update MQTT broker IP in scripts (default: 192.168.0.221)
echo.
echo 3. Run components:
echo    python coordinator.py --broker 192.168.0.221
echo    python attack_simulator.py --broker 192.168.0.221
echo    python dashboard.py --broker 192.168.0.221
echo.
echo For automated demo:
echo    python demo_run.py --broker 192.168.0.221
echo.
pause
'