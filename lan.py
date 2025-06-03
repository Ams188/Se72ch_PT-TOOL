#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import getpass
import stat

def find_se72ch_directory():
    """Search for the se72ch directory in the same directory as this script."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    source_dir = os.path.join(script_dir, "se72ch")
    
    # Check if se72ch directory exists
    if not os.path.isdir(source_dir):
        print(f"Error: se72ch directory not found in {script_dir}")
        sys.exit(1)
    
    # Verify GUI.py exists in se72ch
    gui_path = os.path.join(source_dir, "GUI.py")
    if not os.path.isfile(gui_path):
        print(f"Error: GUI.py not found in {source_dir}")
        sys.exit(1)
    
    print(f"Found se72ch at {source_dir}")
    return source_dir

def install_tool():
    """Copy se72ch directory to /opt/se72ch."""
    source_dir = find_se72ch_directory()
    install_dir = "/opt/se72ch"
    main_script = os.path.join(install_dir, "GUI.py")

    # Create installation directory (may require sudo)
    try:
        if os.path.exists(install_dir):
            print(f"Warning: {install_dir} already exists. Overwriting...")
            shutil.rmtree(install_dir)
        os.makedirs(install_dir, exist_ok=True)
    except PermissionError:
        print(f"Error: No permission to create {install_dir}. Trying with sudo...")
        try:
            subprocess.run(["sudo", "mkdir", "-p", install_dir], check=True)
            subprocess.run(["sudo", "chmod", "755", install_dir], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to create {install_dir} with sudo: {e}")
            sys.exit(1)

    # Copy se72ch directory to /opt/se72ch
    try:
        shutil.copytree(source_dir, install_dir, dirs_exist_ok=True)
        print(f"Copied {source_dir} to {install_dir}")
    except PermissionError:
        print(f"Error: No permission to copy to {install_dir}. Trying with sudo...")
        try:
            subprocess.run(["sudo", "cp", "-r", source_dir, "/opt"], check=True)
            subprocess.run(["sudo", "chmod", "-R", "755", install_dir], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to copy {source_dir} to {install_dir} with sudo: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"Error copying {source_dir} to {install_dir}: {e}")
        sys.exit(1)

    # Verify GUI.py exists
    if not os.path.isfile(main_script):
        print(f"Error: {main_script} not found in {install_dir}.")
        sys.exit(1)

    # Ensure GUI.py is executable
    try:
        os.chmod(main_script, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"Made {main_script} executable")
    except Exception as e:
        print(f"Error setting permissions on {main_script}: {e}")
        sys.exit(1)

    return main_script

def create_launcher(main_script):
    """Create se72ch.desktop launcher in ~/.local/share/applications/."""
    desktop_file_name = "se72ch.desktop"
    desktop_file_path = os.path.expanduser(f"~/.local/share/applications/{desktop_file_name}")
    python_path = "/usr/bin/python3"
    icon_path = "/usr/share/icons/hicolor/48x48/apps/python.png"  # Fallback icon

    # Check if Python exists
    if not os.path.isfile(python_path):
        try:
            python_path = subprocess.check_output(["which", "python3"]).decode().strip()
            if not python_path:
                raise FileNotFoundError
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Error: python3 not found in PATH. Please ensure Python is installed.")
            sys.exit(1)

    # Check if amarok icon exists, else use fallback
    amarok_icon = "/usr/share/icons/hicolor/48x48/apps/amarok.png"
    if os.path.isfile(amarok_icon):
        icon_path = "amarok"
    else:
        print("Warning: amarok icon not found. Using default Python icon.")

    # Content of the .desktop file
    desktop_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=se72ch
Comment=Ethical Hacking Tool GUI
Exec={python_path} {main_script}
Icon={icon_path}
Path={os.path.dirname(main_script)}
Terminal=false
StartupNotify=false
Categories=Utility;Security;
"""

    # Create applications directory if it doesn't exist
    app_dir = os.path.expanduser("~/.local/share/applications")
    os.makedirs(app_dir, exist_ok=True)

    # Write the .desktop file
    try:
        with open(desktop_file_path, "w") as f:
            f.write(desktop_content)
        print(f"Created {desktop_file_path}")
    except PermissionError:
        print(f"Error: No permission to write to {desktop_file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error writing {desktop_file_path}: {e}")
        sys.exit(1)

    # Make the .desktop file executable
    try:
        os.chmod(desktop_file_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"Made {desktop_file_path} executable")
    except Exception as e:
        print(f"Error setting permissions on {desktop_file_path}: {e}")
        sys.exit(1)

    print("Launcher created successfully. Search for 'se72ch' in the applications menu to launch the tool.")

if __name__ == "__main__":
    try:
        main_script = install_tool()
        create_launcher(main_script)
    except KeyboardInterrupt:
        print("\nInstallation cancelled by user.")
        sys.exit(1)
