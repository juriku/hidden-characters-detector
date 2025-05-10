# Hidden Characers Unicode Marker Detector

A Python utility for detecting and cleaning hidden Unicode markers, invisible characters, typographic markers, and other special characters that may be used as watermarks or cause issues in text files.

**Version:** 1.0.0

## What It Does

This tool scans text files for various Unicode characters that are often used as hidden watermarks or may cause formatting issues. It can detect:

- **Hidden markers**: Zero-width spaces, joiners, non-breaking spaces, and other invisible characters
- **Typographic markers**: Smart quotes, em dashes, en dashes, etc.
- **Ideographic Variation Selectors**: Characters used for variant forms of CJK ideographs

The tool can operate in detection-only mode or can clean files by removing or replacing problematic characters.

## Features

- Scan individual files, entire directories (with recursive option), or standard input
- Detect a comprehensive set of hidden Unicode markers
- Optional detection of typographic markers and ideographic variation selectors
- Clean files by removing hidden markers or replacing typographic markers with ASCII equivalents
- Color-coded output for easy visualization
- Detailed reporting with customizable verbosity
- Support for custom character exclusions
- File pattern filtering
- Directory exclusion for recursive scans

## Installation

### Prerequisites

- Python 3.12 or higher

### Setup

1. Download the `hidden-characters-detector.py` script
2. Make it executable (Linux/macOS): `chmod +x hidden-characters-detector.py`
3. Run it from the command line

## Usage

```
./hidden-characters-detector.py [-h] (-f FILE | -d DIR | --stdin) [-r]
                             [--ignore-dir DIRNAME] [--pattern PATTERN]
                             [-c] [-y] [--exclude-char U+XXXX or Char]
                             [--fail] [--check-typographic] [--check-ivs]
                             [--no-color] [--report-file FILE]
                             [--report-mode {normal,quiet,verbose}]
                             [--log-level {DEBUG,INFO,WARNING,ERROR}]
                             [--log-file FILE] [--version]
```

## Options

### Input Options
- `-f FILE, --file FILE`: Path to a single file to check
- `-d DIR, --dir DIR`: Path to a directory to check
- `--stdin`: Read from standard input

### Directory Options
- `-r, --recursive`: Recursively search in subdirectories (used with -d/--dir)
- `--ignore-dir DIRNAME`: Directory name(s) to ignore during recursive scan (e.g., .git)
- `--pattern PATTERN`: File pattern(s) to include (e.g., *.py)

### Processing Options
- `-c, --clean`: Automatically clean/replace detected markers
- `-y, --yes`: Automatically confirm 'yes' to prompts when cleaning files
- `--exclude-char U+XXXX or Char`: Unicode character(s) to exclude from detection/cleaning
- `--fail`: Exit with status code 1 if any specified markers are detected/changed
- `--check-typographic`: Enable the check for specified typographic markers
- `--check-ivs`: Enable the check for Ideographic Variation Selectors

### Output Options
- `--no-color`: Disable colored output
- `--report-file FILE`: Write detailed report to a file
- `--report-mode {normal,quiet,verbose}`: Set the level of reporting detail
- `--log-level {DEBUG,INFO,WARNING,ERROR}`: Set the logging level
- `--log-file FILE`: Write logs to a file instead of stdout

## Examples

### Basic Usage

Check a single file for hidden markers:
```
./hidden-characters-detector.py -f myfile.txt
```

Check a directory recursively for hidden markers:
```
./hidden-characters-detector.py -d project/ -r
```

### Cleaning Files

Check and clean a file (removing hidden markers):
```
./hidden-characters-detector.py -f myfile.txt -c
```

Check and clean a directory with automatic confirmation:
```
./hidden-characters-detector.py -d project/ -r -c -y
```

### Advanced Usage

Check for both hidden and typographic markers, excluding en-dashes:
```
./hidden-characters-detector.py -f myfile.txt --check-typographic --exclude-char U+2013
```

Check for all types of markers and clean a directory:
```
./hidden-characters-detector.py -d docs/ -r -c --check-typographic --check-ivs
```

Pipe content to check for markers:
```
cat myfile.txt | ./hidden-characters-detector.py --stdin
```

### CI/CD Integration

Fail if any markers are detected (useful for CI/CD pipelines):
```
./hidden-characters-detector.py -d src/ -r --fail
```

## What Gets Detected

### Hidden Markers (Detected by Default)

The tool detects a comprehensive set of hidden markers, including:
- Zero Width Space (U+200B)
- Zero Width Non-Joiner (U+200C)
- Zero Width Joiner (U+200D)
- Word Joiner (U+2060)
- Byte Order Mark (U+FEFF)
- Various space characters (non-breaking space, thin space, etc.)
- Directional formatting characters
- Variation selectors
- And many more

### Typographic Markers (Optional)

When enabled with `--check-typographic`, detects:
- Smart/curly quotes (U+2018, U+2019, U+201C, U+201D)
- En Dash (U+2013)
- Em Dash (U+2014)
- Horizontal Ellipsis (U+2026)

### Ideographic Variation Selectors (Optional)

When enabled with `--check-ivs`, detects Ideographic Variation Selectors (VS17-VS256, U+E0100 to U+E01EF).

## Cleaning Behavior

When used with the `-c` or `--clean` option:

- **Hidden markers** are removed completely
- **Typographic markers** are replaced according to predefined rules:
  - Smart quotes → Straight quotes
  - Em/En dashes → Hyphen-minus
- **Ideographic Variation Selectors** are removed

## Use Cases

- Detecting potential hidden watermarks or steganography using invisible characters
- Normalizing text files for consistent formatting
- Cleaning log files or text data containing unwanted watermarks
- Detecting potentially problematic Ideographic Variation Selectors (IVS)
- Preparing code or text for environments with limited Unicode support
- Ensuring clean, consistent text output
- CI/CD pipeline verification workflows to ensure text file hygiene (`--fail` option)
- Checking for unintended or malicious invisible characters

## License

This script is released under the **MIT License**. See the `LICENSE` file for the full text.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.