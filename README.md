# Cli pcap Sweeper Setup

This setup script automatically installs and configures a Python-based CLI script that analyses pcaps. It runs Zeek network analysis in Docker containers.
* install OS package dependencies
* create python virtual env
* install python libraries
* prefetch zeek docker container
* deploy the python script
* deploy the shell wrapper scripts that activates python venv and runs the script

# PCAP Sweeper runs the following analyses

* Detects queries with high latency.
* Detects high rates of SERVFAIL and NXDOMAIN errors.
* Identifies queries that do not have a corresponding response.
* Checks for inconsistencies in TTLs for the same domain. (**WARNING: this one has bad logic, outputs bogus results**)

**WARNING: Not properly tested, do not use the produced data as source of truth**



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
- **Docker** - For running Zeek in containers
- **Git** (optional) - For cloning repositories

### Automatic Installation

If requirements are missing, the script will provide installation commands for your system:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip docker.io git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install python3 python3-pip docker git
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

# Uninstall / reove the script

TODO - bellow is the list of files and modification performed by the installer, so remove manually for now
* Bash shell wrapper file is deployed in ~/.local/bin/pcap-analyzer
* Python script ~/.local/share/pcap-analyzer/pcap-analyzer.py
* Python virtual environment ~/.local/share/pcap-analyzer/venv
