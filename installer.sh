#!/bin/bash

# Docker Python Script Setup Script
# This script sets up a Python script that runs commands in Docker containers

set -e  # Exit on any error

# Configuration
SCRIPT_NAME="zeek-analyzer"
PYTHON_SCRIPT_NAME="zeek_runner.py"
DOCKER_IMAGE="zeek/zeek:latest"
INSTALL_DIR="$HOME/.local/bin"
SCRIPT_DIR="$HOME/.local/share/$SCRIPT_NAME"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        local python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        local required_version="3.6"
        
        if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# Function to check requirements
check_requirements() {
    local missing_requirements=()
    
    log_info "Checking system requirements..."
    
    # Check Python
    if ! check_python_version; then
        missing_requirements+=("python3 (version 3.6 or higher)")
    fi
    
    # Check Docker
    if ! command_exists docker; then
        missing_requirements+=("docker")
    elif ! docker info >/dev/null 2>&1; then
        log_warning "Docker is installed but not running or accessible. You may need to:"
        log_warning "  - Start Docker service: sudo systemctl start docker"
        log_warning "  - Add user to docker group: sudo usermod -aG docker \$USER"
        log_warning "  - Log out and back in for group changes to take effect"
    fi
    
    # Check Git (optional but recommended)
    if ! command_exists git; then
        log_warning "Git is not installed. This is optional but recommended."
    fi
    
    # Report missing requirements
    if [ ${#missing_requirements[@]} -ne 0 ]; then
        log_error "Missing requirements:"
        for req in "${missing_requirements[@]}"; do
            echo "  - $req"
        done
        echo ""
        echo "Please install missing requirements and run this script again."
        echo ""
        echo "Installation commands (Ubuntu/Debian):"
        echo "  sudo apt update"
        echo "  sudo apt install python3 python3-pip docker.io git"
        echo "  sudo systemctl start docker"
        echo "  sudo systemctl enable docker"
        echo "  sudo usermod -aG docker \$USER"
        echo ""
        echo "Installation commands (CentOS/RHEL/Fedora):"
        echo "  sudo dnf install python3 python3-pip docker git"  # or yum for older versions
        echo "  sudo systemctl start docker"
        echo "  sudo systemctl enable docker"
        echo "  sudo usermod -aG docker \$USER"
        exit 1
    fi
    
    log_success "All requirements met!"
}

# Function to create the Python script
create_python_script() {
    log_info "Creating Python script..."
    
    cat > "$SCRIPT_DIR/$PYTHON_SCRIPT_NAME" << 'EOF'
#!/usr/bin/env python3
"""
PCAP Processing Script
Automates the processing of pcap files with Zeek analysis
"""

import os
import glob
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pcap_processing.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PcapProcessor:
    def __init__(self, source_directory: str):
        """
        Initialize the PCAP processor
        
        Args:
            source_directory (str): Directory containing pcap files
        """
        self.source_directory = Path(source_directory)
        self.pcap_files = []
        self.pcap_directories = []
        
    def scan_directory_for_pcaps(self) -> List[str]:
        """
        Scan directory for pcap files and create a list
        
        Returns:
            List[str]: List of pcap file paths
        """
        logger.info(f"Scanning directory: {self.source_directory}")
        
        # Common pcap file extensions
        pcap_extensions = ['*.pcap', '*.pcapng', '*.cap']
        
        for extension in pcap_extensions:
            pattern = self.source_directory / extension
            files = glob.glob(str(pattern))
            self.pcap_files.extend(files)
        
        logger.info(f"Found {len(self.pcap_files)} pcap files")
        for pcap_file in self.pcap_files:
            logger.info(f"  - {pcap_file}")
            
        return self.pcap_files
    
    def organize_pcap_files(self) -> List[Tuple[str, str]]:
        """
        Create directories for each pcap file and move them
        
        Returns:
            List[Tuple[str, str]]: List of (directory_path, pcap_file_path) tuples
        """
        logger.info("Organizing pcap files into directories")
        
        for pcap_file in self.pcap_files:
            pcap_path = Path(pcap_file)
            
            # Create directory name (filename without extension)
            dir_name = pcap_path.stem
            target_dir = self.source_directory / dir_name
            
            try:
                # Create directory if it doesn't exist
                target_dir.mkdir(exist_ok=True)
                
                # Move pcap file to the new directory
                new_pcap_path = target_dir / pcap_path.name
                shutil.move(str(pcap_path), str(new_pcap_path))
                
                # Update the list with new paths
                self.pcap_directories.append((str(target_dir), str(new_pcap_path)))
                
                logger.info(f"Moved {pcap_file} to {target_dir}")
                
            except Exception as e:
                logger.error(f"Error organizing {pcap_file}: {e}")
                
        return self.pcap_directories
    
    def run_zeek_analysis(self, directory_path: str, pcap_file_path: str) -> bool:
        """
        Run Zeek analysis on pcap file using Docker
        
        Args:
            directory_path (str): Directory containing the pcap file
            pcap_file_path (str): Path to the pcap file
            
        Returns:
            bool: True if successful, False otherwise
        """
        logger.info(f"Running Zeek analysis on {pcap_file_path}")
        
        try:
            # Docker command to run Zeek
            # Mount the directory and run zeek on the pcap file
            docker_cmd = [
                'docker', 'run', '--rm',
                '-v', f'{directory_path}:/data',
                '-w', '/data',
                'zeek/zeek:latest',
                'zeek', '-r', f'/data/{Path(pcap_file_path).name}',
                '-C'  # Run in foreground
            ]
            logger.info(f"Docker-cmd: {docker_cmd}")
            # Change to the target directory for output
            result = subprocess.run(
                docker_cmd,
                cwd=directory_path,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Zeek analysis completed successfully for {pcap_file_path}")
                return True
            else:
                logger.error(f"Zeek analysis failed for {pcap_file_path}")
                logger.error(f"Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Zeek analysis timed out for {pcap_file_path}")
            return False
        except Exception as e:
            logger.error(f"Error running Zeek analysis on {pcap_file_path}: {e}")
            return False
    
    def analyze_pcap_directory(self, directory_path: str) -> dict:
        """
        Dummy analysis function for pcap directory
        This will be developed in later stages
        
        Args:
            directory_path (str): Directory containing pcap and zeek logs
            
        Returns:
            dict: Analysis results (dummy for now)
        """
        logger.info(f"Running analysis on directory: {directory_path}")
        
        # Placeholder analysis logic
        directory = Path(directory_path)
        
        # Count files in directory
        files = list(directory.glob('*'))
        log_files = list(directory.glob('*.log'))
        
        analysis_results = {
            'directory': directory_path,
            'total_files': len(files),
            'log_files': len(log_files),
            'analysis_status': 'completed',
            'timestamp': Path(directory_path).stat().st_mtime if directory.exists() else None
        }
        
        logger.info(f"Analysis completed for {directory_path}: {analysis_results}")
        return analysis_results
    
    def generate_report(self, all_analysis_results: List[dict]) -> dict:
        """
        Dummy report generation function
        This will be developed in later stages
        
        Args:
            all_analysis_results (List[dict]): Results from all analyses
            
        Returns:
            dict: Generated report (dummy for now)
        """
        logger.info("Generating final report")
        
        total_directories = len(all_analysis_results)
        successful_analyses = len([r for r in all_analysis_results if r.get('analysis_status') == 'completed'])
        
        report = {
            'total_pcap_files_processed': total_directories,
            'successful_analyses': successful_analyses,
            'failed_analyses': total_directories - successful_analyses,
            'report_timestamp': Path.cwd().stat().st_mtime,
            'detailed_results': all_analysis_results
        }
        
        # Save report to file
        report_file = self.source_directory / 'processing_report.txt'
        with open(report_file, 'w') as f:
            f.write("PCAP Processing Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Total PCAP files processed: {report['total_pcap_files_processed']}\n")
            f.write(f"Successful analyses: {report['successful_analyses']}\n")
            f.write(f"Failed analyses: {report['failed_analyses']}\n")
            f.write("\nDetailed Results:\n")
            for result in all_analysis_results:
                f.write(f"- {result['directory']}: {result['analysis_status']}\n")
        
        logger.info(f"Report saved to: {report_file}")
        return report
    
    def process_all(self) -> dict:
        """
        Main processing function that orchestrates the entire workflow
        
        Returns:
            dict: Final processing report
        """
        logger.info("Starting PCAP processing workflow")
        
        try:
            # Step 1: Scan for pcap files
            self.scan_directory_for_pcaps()
            
            if not self.pcap_files:
                logger.warning("No pcap files found in directory")
                return {'status': 'no_files_found'}
            
            # Step 2: Organize pcap files into directories
            self.organize_pcap_files()
            
            # Step 3: Run Zeek analysis on each pcap
            zeek_results = []
            for directory_path, pcap_file_path in self.pcap_directories:
                success = self.run_zeek_analysis(directory_path, pcap_file_path)
                zeek_results.append((directory_path, success))
            
            # Step 4: Run analysis function on each directory
            analysis_results = []
            for directory_path, zeek_success in zeek_results:
                result = self.analyze_pcap_directory(directory_path)
                result['zeek_success'] = zeek_success
                analysis_results.append(result)
            
            # Step 5: Generate final report
            final_report = self.generate_report(analysis_results)
            
            logger.info("PCAP processing workflow completed successfully")
            return final_report
            
        except Exception as e:
            logger.error(f"Error in processing workflow: {e}")
            return {'status': 'error', 'message': str(e)}


def main():
    """
    Main function to run the PCAP processor
    """
    # Configuration
    SOURCE_DIRECTORY = os.getcwd() #"/root/my-fastapi-rocket-boilerplate/cli/data"  # Change this to your pcap directory
    
    # Create source directory if it doesn't exist (for testing)
    os.makedirs(SOURCE_DIRECTORY, exist_ok=True)
    
    # Initialize and run processor
    processor = PcapProcessor(SOURCE_DIRECTORY)
    
    try:
        result = processor.process_all()
        print("\n" + "="*50)
        print("PROCESSING COMPLETE")
        print("="*50)
        print(f"Result: {result}")
        
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
EOF

    chmod +x "$SCRIPT_DIR/$PYTHON_SCRIPT_NAME"
    log_success "Python script created at $SCRIPT_DIR/$PYTHON_SCRIPT_NAME"
}

# Function to create wrapper script
create_wrapper_script() {
    log_info "Creating wrapper script..."
    
    cat > "$INSTALL_DIR/$SCRIPT_NAME" << EOF
#!/bin/bash
# Wrapper script for $SCRIPT_NAME
exec python3 "$SCRIPT_DIR/$PYTHON_SCRIPT_NAME" "\$@"
EOF

    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    log_success "Wrapper script created at $INSTALL_DIR/$SCRIPT_NAME"
}

# Function to pull Docker image
pull_docker_image() {
    log_info "Pulling Docker image: $DOCKER_IMAGE"
    
    if docker pull "$DOCKER_IMAGE"; then
        log_success "Docker image pulled successfully"
    else
        log_error "Failed to pull Docker image. Please check your internet connection and Docker setup."
        exit 1
    fi
}

# Function to setup shell alias
setup_alias() {
    local shell_config=""
    local shell_name=$(basename "$SHELL")
    
    # Determine shell configuration file
    case "$shell_name" in
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                shell_config="$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                shell_config="$HOME/.bash_profile"
            fi
            ;;
        zsh)
            shell_config="$HOME/.zshrc"
            ;;
        fish)
            # Fish uses a different syntax, handle separately
            log_info "Detected Fish shell. Adding to Fish config..."
            mkdir -p "$HOME/.config/fish"
            echo "set -gx PATH $INSTALL_DIR \$PATH" >> "$HOME/.config/fish/config.fish"
            log_success "Added to Fish PATH. Restart your shell or run 'source ~/.config/fish/config.fish'"
            return
            ;;
        *)
            log_warning "Unknown shell: $shell_name. You may need to manually add $INSTALL_DIR to your PATH."
            ;;
    esac
    
    if [ -n "$shell_config" ] && [ -f "$shell_config" ]; then
        # Check if PATH update already exists
        if ! grep -q "$INSTALL_DIR" "$shell_config"; then
            echo "" >> "$shell_config"
            echo "# Added by $SCRIPT_NAME setup script" >> "$shell_config"
            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$shell_config"
            log_success "Added $INSTALL_DIR to PATH in $shell_config"
            log_info "Restart your shell or run 'source $shell_config' to use the new command"
        else
            log_info "$INSTALL_DIR already in PATH"
        fi
    else
        log_warning "Could not determine shell configuration file. Please manually add $INSTALL_DIR to your PATH."
    fi
}

# Function to create directories
create_directories() {
    log_info "Creating directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$SCRIPT_DIR"
    log_success "Directories created"
}

# Function to run tests
run_tests() {
    log_info "Running basic tests..."
    
    # Test if script is accessible
    if [ -x "$INSTALL_DIR/$SCRIPT_NAME" ]; then
        log_success "Script is executable"
    else
        log_error "Script is not executable"
        return 1
    fi
    
    # Test Docker image
    if docker images | grep -q "zeek/zeek"; then
        log_success "Docker image is available"
    else
        log_warning "Docker image not found locally"
    fi
    
    log_success "Basic tests completed"
}

 
# Main installation function
main() {
    echo "======================================"
    echo "  $SCRIPT_NAME Setup Script"
    echo "======================================"
    echo ""
    
    # Check requirements first
    check_requirements
    
    # Create directories
    create_directories
    
    # Create Python script
    create_python_script
    
    # Create wrapper script
    create_wrapper_script
    
    # Pull Docker image
    pull_docker_image
    
    # Setup shell alias/PATH
    setup_alias
    
    # Run tests
    run_tests
    
    echo ""
    echo "======================================"
    log_success "Installation completed successfully!"
    echo "======================================"
    echo ""
    echo "Usage:"
    echo "  $SCRIPT_NAME <pcap_file>                    # Basic analysis"
    echo "  $SCRIPT_NAME <pcap_file> -- <zeek_args>     # With additional Zeek arguments"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME sample.pcap"
    echo "  $SCRIPT_NAME sample.pcap -- --help"
    echo "  $SCRIPT_NAME sample.pcap -- -v -C"
    echo ""
    echo "Note: If the command is not found, restart your shell or run:"
    echo "  source ~/.bashrc  (for bash)"
    echo "  source ~/.zshrc   (for zsh)"
    echo ""
    echo "Or run directly with:"
    echo "  $INSTALL_DIR/$SCRIPT_NAME <pcap_file>"
}

# Run main function
main "$@"