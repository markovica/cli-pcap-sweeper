# Cli pcap Sweeper Setup

This setup script automatically installs and configures a Python-based CLI script that analyses pcaps. It runs Zeek network analysis in Docker containers.

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
