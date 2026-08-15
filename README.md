# Hidden Characers Unicode Marker Detector

A Python utility for detecting and cleaning hidden Unicode markers, invisible characters, typographic markers, and other special characters that may be used as watermarks or cause issues in text files.

**Version:** 1.2.0

## website version: [ai-detect.devbox.buzz](https://ai-detect.devbox.buzz)

## What It Does

This tool scans text files for various Unicode characters that are often used as hidden watermarks or may cause formatting issues. It can detect:

- **Hidden markers**: Zero-width spaces, joiners, non-breaking spaces, and other invisible characters
- **Typographic markers**: Smart quotes, em dashes, en dashes, etc.
- **Ideographic Variation Selectors**: Characters used for variant forms of CJK ideographs

The tool can operate in detection-only mode or can clean files by removing or replacing problematic characters.

## Features

- Scan individual files, entire directories (recursive by default), or standard input
- When no input is given, scans the current directory by default
- Detect a comprehensive set of hidden Unicode markers, typographic markers, and ideographic variation selectors (all enabled by default)
- Honors `.gitignore` files (including nested ones) out of the box
- Skips dependency and cache directories by default (`node_modules`, `__pycache__`, `.venv`, `.terraform`, and more)
- Clean files by removing hidden markers or replacing typographic markers with ASCII equivalents
- Color-coded output for easy visualization
- Detailed reporting with customizable verbosity
- Support for custom character exclusions
- File pattern filtering
- Directory exclusion for recursive scans

## Installation

### Prerequisites

- Python 3.12 or higher

### Dependencies

```
pip install -r requirements.txt
```

- `emoji` (optional) - suppresses false positives when `\uFE0F` forms a real emoji sequence
- `pathspec` (optional) - required for `.gitignore` support; without it, `.gitignore` files are silently ignored

### Setup

1. Download the `hidden-characters-detector.py` script
2. Make it executable (Linux/macOS): `chmod +x hidden-characters-detector.py`
3. Run it from the command line

## Usage

```
# Scan the current directory recursively - recursive, typographic, and IVS checks are all on by default
./hidden-characters-detector.py

# Clean everything in the current directory (honors .gitignore)
./hidden-characters-detector.py -c -y

./hidden-characters-detector.py [-h] [-f FILE | -d [DIR] | --stdin] [-r | --no-recursive]
                             [--ignore-dir DIRNAME] [--no-default-ignores]
                             [--no-gitignore] [--pattern PATTERN]
                             [-c] [-y] [--exclude-char U+XXXX or Char]
                             [--word] [--fail]
                             [--check-typographic | --no-check-typographic]
                             [--check-ivs | --no-check-ivs]
                             [--no-color] [--report-file FILE]
                             [--report-mode {normal,quiet,verbose}]
                             [--log-level {DEBUG,INFO,WARNING,ERROR}]
                             [--log-file FILE] [--version]
```

Running with no arguments defaults to `-d .` (scan the current directory). Add a function to `.bashrc` and change `${CLONE_DIR}`:

```
function hidden() {
  local script="${CLONE_DIR}/hidden-characters-detector/hidden-characters-detector.py"
  local target_opt_array=("-d")
  local target_val="."
  if [[ -n "$1" ]]; then
    if [[ -f "$1" ]]; then
      target_opt_array=("-f"); target_val="$1"; shift
    elif [[ -d "$1" ]]; then
      target_val="$1"; shift
    fi
  fi
  python "$script" -c --ignore-dir ".terraform" "${target_opt_array[@]}" "$target_val" "$@"
}
```

## Options

### Input Options
- `-f FILE, --file FILE`: Path to a single file to check
- `-d [DIR], --dir [DIR]`: Path to a directory to check. If omitted, defaults to `.`. If no input flag is given at all, the script also defaults to scanning the current directory.
- `--stdin`: Read from standard input

### Directory Options
- `-r, --recursive` / `--no-recursive`: Recursively search subdirectories. **Default: on.**
- `--ignore-dir DIRNAME`: Additional directory name(s) to ignore during recursive scan (repeatable). Adds to the built-in list rather than replacing it.
- `--no-default-ignores`: Descend into the built-in dependency/cache directories. `.git` is skipped either way.
- `--no-gitignore`: Do not honor `.gitignore` files encountered during the scan. By default, nested `.gitignore` files are applied to their own subtree.
- `--pattern PATTERN`: File pattern(s) to include (e.g., `*.py`)

### Processing Options
- `-c, --clean`: Automatically clean/replace detected markers
- `-y, --yes`: Automatically confirm 'yes' to prompts when cleaning files
- `--exclude-char U+XXXX or Char`: Unicode character(s) to exclude from detection/cleaning
- `--word`: Exclude characters commonly auto-corrected by Microsoft Word
- `--fail`: Exit with status code 1 if any specified markers are detected/changed
- `--check-typographic` / `--no-check-typographic`: Detect typographic markers. **Default: on.**
- `--check-ivs` / `--no-check-ivs`: Detect Ideographic Variation Selectors. **Default: on.**

### Output Options
- `--no-color`: Disable colored output
- `--report-file FILE`: Write detailed report to a file
- `--report-mode {normal,quiet,verbose}`: Set the level of reporting detail
- `--log-level {DEBUG,INFO,WARNING,ERROR}`: Set the logging level
- `--log-file FILE`: Write logs to a file instead of stdout

## Examples

### Basic Usage

Scan the current directory (recursive, all checks on, `.git` and `.gitignore` entries skipped):
```
./hidden-characters-detector.py
```

Check a single file:
```
./hidden-characters-detector.py -f myfile.txt
```

Top-level only (do not descend into subdirectories):
```
./hidden-characters-detector.py -d project/ --no-recursive
```

### Cleaning Files

Check and clean a file (removing hidden markers, replacing typographic ones):
```
./hidden-characters-detector.py -f myfile.txt -c
```

Clean a directory with automatic confirmation:
```
./hidden-characters-detector.py -d project/ -c -y
```

### Advanced Usage

Detect hidden markers only (skip typographic and IVS checks), and exclude en-dashes:
```
./hidden-characters-detector.py -f myfile.txt --no-check-typographic --no-check-ivs --exclude-char U+2013
```

Scan without honoring `.gitignore`:
```
./hidden-characters-detector.py --no-gitignore
```

Ignore extra directories on top of the built-in list:
```
./hidden-characters-detector.py --ignore-dir fixtures --ignore-dir third_party
```

Scan everything, including dependency and cache directories:
```
./hidden-characters-detector.py --no-default-ignores --no-gitignore
```

Pipe content to check for markers:
```
cat myfile.txt | ./hidden-characters-detector.py --stdin
```

In `--stdin` mode stdout carries only the document, and the report goes to
stderr, so cleaned text can be redirected safely:
```
cat myfile.txt | ./hidden-characters-detector.py --stdin -c -y > cleaned.txt
```

### CI/CD Integration

Fail if any markers are detected (useful for CI/CD pipelines):
```
./hidden-characters-detector.py -d src/ --fail
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

### Typographic Markers (Detected by Default)

Enabled by default; disable with `--no-check-typographic`. Detects:
- Smart/curly quotes (U+2018, U+2019, U+201C, U+201D)
- En Dash (U+2013)
- Em Dash (U+2014)
- Horizontal Ellipsis (U+2026)
- Cyrillic/Greek homoglyphs and many more

### Disable common Microsoft Word character replacements

When enabled with `--word`, excludes common Microsoft Word typographic replacements that are automatically converted in Word.

### Ideographic Variation Selectors (Detected by Default)

Enabled by default; disable with `--no-check-ivs`. Detects Ideographic Variation Selectors (VS17-VS256, U+E0100 to U+E01EF).

### `.gitignore` Handling (On by Default)

By default the scanner loads a `.gitignore` from the root directory and any nested subdirectories, applying each file's patterns within its own subtree (matching Git's semantics, including negation with `!`). Disable with `--no-gitignore`. Requires the `pathspec` package - without it, `.gitignore` files are silently skipped.

### Directories Skipped by Default (Recursive Scans)

Independent of `.gitignore`, these directory names are skipped during recursive scans, which keeps the scan fast and quiet in a directory that is not a git repo, has no `.gitignore`, or is scanned with `--no-gitignore`:

`.angular`, `.astro`, `.bundle`, `.cache`, `.dart_tool`, `.eggs`, `.git`, `.gradle`, `.hg`, `.mypy_cache`, `.next`, `.nox`, `.nuxt`, `.nyc_output`, `.parcel-cache`, `.pnpm-store`, `.pytest_cache`, `.pytype`, `.ruff_cache`, `.sass-cache`, `.serverless`, `.svelte-kit`, `.svn`, `.terraform`, `.tox`, `.turbo`, `.venv`, `.vite`, `.yarn`, `Pods`, `__pycache__`, `bower_components`, `htmlcov`, `jspm_packages`, `node_modules`, `venv`

Ambiguous names such as `build`, `dist`, `out`, `target`, `bin`, `obj`, and `vendor` are **not** on this list, because they are hand-written source directories in some projects and skipping them would hide real markers. Add them yourself with `--ignore-dir` where they are build output.

Use `--no-default-ignores` to scan these directories anyway (`.git` stays skipped).

## Cleaning Behavior

When used with the `-c` or `--clean` option:

- **Hidden markers** are removed completely, except non-standard spaces
  (non-breaking space, thin space, ideographic space, etc.) which are replaced
  with a regular space (U+0020) so word boundaries survive cleaning
- **Typographic markers** are replaced according to predefined rules:
  - Smart quotes → Straight quotes
  - Em/En dashes → Hyphen-minus
- **Ideographic Variation Selectors** are removed

Cleaning writes each file back in its original encoding. If a file cannot be
decoded cleanly it is skipped with an error rather than rewritten, so cleaning
never transcodes or mangles a file.

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