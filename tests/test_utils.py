# test_utils.py (or place at the top of each test file if not using a shared utils file)
import subprocess
import tempfile
import os
import shutil
import sys
from pathlib import Path

# Define paths relative to the test script's location
BASE_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = BASE_DIR / "../hidden-characters-detector.py"

# Ensure the script exists and is executable
if not SCRIPT_PATH.exists():
    print(f"ERROR: Script not found at {SCRIPT_PATH}", file=sys.stderr)
    sys.exit(1)
# On Unix-like systems, you might want to ensure it's executable,
# though python3 interpreter will be used directly.
# os.chmod(SCRIPT_PATH, 0o755)


# Marker constants for convenience
ZERO_WIDTH_SPACE = '\u200B'
NON_BREAKING_SPACE = '\u00A0'
EM_DASH = '\u2014'
LEFT_DOUBLE_QUOTE = '\u201C'
RIGHT_DOUBLE_QUOTE = '\u201D'
HYPHEN_MINUS = '\u002D'
STRAIGHT_DOUBLE_QUOTE = '"'
IDEOGRAPHIC_VS = chr(0xE0101)
BOM = '\uFEFF'
NORMAL_TEXT = "Hello world"

def run_script(args, stdin_data=None):
    """
    Runs the hidden-characters-detector.py script with given arguments.

    Args:
        args (list): A list of command-line arguments for the script.
        stdin_data (str, optional): String data to pass to the script's stdin.

    Returns:
        subprocess.CompletedProcess: The result of the script execution.
    """
    command = [sys.executable, str(SCRIPT_PATH)] + args
    # print(f"Running command: {' '.join(command)}", file=sys.stderr) # For debugging
    process = subprocess.run(
        command,
        input=stdin_data,
        capture_output=True,
        text=True,
        encoding='utf-8' # Ensure consistent encoding for IO
    )
    return process

def create_temp_file(dir_path, name="test_file.txt", content="", encoding='utf-8', perms=None):
    """Creates a temporary file with given content and returns its Path object."""
    file_path = Path(dir_path) / name
    with open(file_path, "w", encoding=encoding) as f:
        f.write(content)
    if perms is not None:
        os.chmod(file_path, perms)
    return file_path

def read_file_content(file_path, encoding='utf-8'):
    """Reads and returns the content of a file."""
    try:
        with open(file_path, "r", encoding=encoding) as f:
            return f.read()
    except FileNotFoundError:
        return None # Or raise error, depending on test needs