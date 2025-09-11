# Cli pcap Sweeper Setup

This setup script automatically installs and configures a Python-based CLI script that analyses pcaps. It runs Zeek network analysis in Docker containers.
* install OS package dependencies
* create python virtual env
* install python libraries
* prefetch zeek docker container
* deploy the python script
* deploy the shell wrapper scripts that activates python venv and runs the script

# PCAP Sweeper runs the following analyses

* Detects queries with high latency (above 2000ms) and saves a CSV report
* Detects high rates of SERVFAIL and NXDOMAIN errors and saves a CSV report for each
* Identifies queries that do not have a corresponding response and saves a CSV report



## Quick Start

### 1. Download and run the setup script:

```bash
# Option 1: Direct download and execute
curl -sSL https://raw.githubusercontent.com/markovica/cli-pcap-sweeper/refs/heads/main/installer.sh | bash

# Option 2: Download first, then execute
wget https://raw.githubusercontent.com/markovica/cli-pcap-sweeper/refs/heads/main/installer.sh
chmod +x setup.sh
./setup.sh

# Option 3: Clone the repository
git clone https://github.com/markovica/cli-pcap-sweeper.git
cd zeek-helper-script
./setup.sh
```

### 2. Restart your shell or source your configuration:

```bash
# For Bash
source ~/.bashrc

# For Zsh
source ~/.zshrc

# Or simply restart your terminal
```

### 3. Run PCAP Sweeper

Run the following command in the directory where you have stored pcaps for porcessing/analysis:
```bash
pcap-analyzer
```

## Requirements

The setup script will automatically check for these requirements:

- **Python 3.6+** - For running the wrapper script
- **python3-venv** - For creating isolated Python environments
- **python3-pip** - For installing Python packages
- **Docker** - For running Zeek in containers
- **Git** (optional) - For cloning repositories

### Automatic Installation

If requirements are missing, the script will provide installation commands for your system:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv docker.io git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install python3 python3-pip python3-venv docker git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

http://192.168.1.11:6875/link/211#bkmrk-%2A%2Aarch-linux%3A%2A%2A%60%60%60ba
 
**Arch Linux:**
```bash
sudo pacman -S python python-pip docker git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

# Uninstall / reove the script

TODO - bellow is the list of files and modification performed by the installer, so remove manually for now
* Bash shell wrapper file is deployed in ~/.local/bin/pcap-sweeper
* Python script ~/.local/share/pcap-sweeper/pcap-sweeper.py
* Python virtual environment ~/.local/share/pcap-sweeper/venv
