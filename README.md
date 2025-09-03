# Zeek Docker Analyzer Setup

This setup script automatically installs and configures a Python-based wrapper for running Zeek network analysis in Docker containers.

## Quick Start

### 1. Download and run the setup script:

```bash
# Option 1: Direct download and execute
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/setup.sh | bash

# Option 2: Download first, then execute
wget https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/setup.sh
chmod +x setup.sh
./setup.sh

# Option 3: Clone the repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
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

## Usage

Once installed, you can use the `zeek-analyzer` command:

### Basic Usage:
```bash
# Analyze a PCAP file
zeek-analyzer sample.pcap

# The tool will create analysis files in the same directory as your PCAP
```

### Advanced Usage with Zeek Arguments:
```bash
# Get Zeek help
zeek-analyzer sample.pcap -- --help

# Run with verbose output
zeek-analyzer sample.pcap -- -v

# Use custom Zeek scripts
zeek-analyzer sample.pcap -- -C local.zeek

# Multiple Zeek arguments
zeek-analyzer sample.pcap -- -v -C -s signatures.sig
```

### Manual Execution (if PATH setup fails):
```bash
# Run directly from installation directory
~/.local/bin/zeek-analyzer sample.pcap

# Or run the Python script directly
python3 ~/.local/share/zeek-analyzer/zeek_runner.py sample.pcap
```

## What the Setup Script Does

1. **Requirements Check**: Validates Python, Docker, and other dependencies
2. **Directory Creation**: Sets up `~/.local/bin` and `~/.local/share/zeek-analyzer`
3. **Script Installation**: Creates the Python wrapper and shell script
4. **Docker Image**: Pre-pulls the `zeek/zeek:latest` container image
5. **PATH Setup**: Adds the script to your shell PATH for easy access
6. **Testing**: Verifies the installation works correctly

## File Locations

- **Executable**: `~/.local/bin/zeek-analyzer`
- **Python Script**: `~/.local/share/zeek-analyzer/zeek_runner.py`
- **Shell Config**: Updated `~/.bashrc` or `~/.zshrc`

## Troubleshooting

### Command Not Found
```bash
# Manually add to PATH (temporary)
export PATH="$HOME/.local/bin:$PATH"

# Or source your shell config
source ~/.bashrc  # or ~/.zshrc
```

### Docker Permission Issues
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Start Docker service
sudo systemctl start docker

# Log out and back in for group changes
```

### Docker Image Issues
```bash
# Manually pull the image
docker pull zeek/zeek:latest

# Check Docker is running
docker info
```

### Python Issues
```bash
# Check Python version
python3 --version

# Install if missing (Ubuntu/Debian)
sudo apt install python3
```

## Uninstallation

To remove the installed components:

```bash
# Remove scripts
rm -f ~/.local/bin/zeek-analyzer
rm -rf ~/.local/share/zeek-analyzer

# Remove Docker image (optional)
docker rmi zeek/zeek:latest

# Remove PATH entry from shell config (manual step)
# Edit ~/.bashrc or ~/.zshrc and remove the added export line
```

## Repository Structure

```
your-repo/
├── setup.sh              # Main setup script
├── README.md             # This file
└── examples/
    └── sample.pcap       # Example PCAP file (if included)
```

## Contributing

Feel free to submit issues and pull requests to improve this tool.

## License

[Add your license here]

## How to Use This Setup

Here's how to deploy and use this setup script:

### 1. **Create Your GitHub Repository**

1. Create a new repository on GitHub
2. Save the bash script as `setup.sh` in the root of your repository
3. Include the README.md for documentation
4. Make sure to update the README URLs with your actual GitHub username and repository name

### 2. **Repository Structure**
```
your-repo/
├── setup.sh              # The main setup script
├── README.md             # Documentation and usage instructions
└── examples/             # Optional: example PCAP files
    └── sample.pcap
```

### 3. **Usage Examples**

Once users run your setup script, they can use the tool like this:

```bash
# Basic usage
zeek-analyzer capture.pcap

# With additional Zeek arguments
zeek-analyzer capture.pcap -- --help
zeek-analyzer capture.pcap -- -v -C
zeek-analyzer capture.pcap -- -s custom.zeek

# View help
zeek-analyzer --help
```

### 4. **Key Features of the Setup Script**

- **Comprehensive Requirements Checking**: Validates Python, Docker, and provides installation instructions
- **Cross-Platform Shell Support**: Works with Bash, Zsh, and Fish shells
- **Error Handling**: Robust error checking with informative messages
- **Docker Management**: Pre-pulls the container image and validates Docker setup
- **PATH Management**: Automatically adds the script to user's PATH
- **Testing**: Runs basic tests to ensure everything works
- **User-Friendly**: Colored output and clear progress indicators

### 5. **Installation Methods for Users**

Users can install your tool in three ways:

```bash
# Method 1: Direct install
curl -sSL https://raw.githubusercontent.com/USERNAME/REPO/main/setup.sh | bash

# Method 2: Download first
wget https://raw.githubusercontent.com/USERNAME/REPO/main/setup.sh
chmod +x setup.sh
./setup.sh

# Method 3: Clone and install
git clone https://github.com/USERNAME/REPO.git
cd REPO
./setup.sh
```

The script handles all the complexity of setting up the Python wrapper, Docker integration, and shell configuration automatically. Users just need to run the setup script once, and then they can use your tool with a simple command-line interface.
