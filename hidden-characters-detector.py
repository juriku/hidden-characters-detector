#!/usr/bin/env python3

import argparse
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# --- Configuration ---
VERSION = "1.0.0"

# --- Marker Definitions ---
# Define common hidden characters often used for watermarking or causing issues

HIDDEN_MARKERS: Dict[str, str] = {
    # Zero Width Characters
    '\u200B': "Zero Width Space (U+200B)",
    '\u200C': "Zero Width Non-Joiner (U+200C)",
    '\u200D': "Zero Width Joiner (U+200D)",
    '\u2060': "Word Joiner (U+2060)",
    '\uFEFF': "Byte Order Mark (BOM) / Zero Width No-Break Space (U+FEFF)",

    # Common Non-Standard Spaces
    '\u00A0': "Non-Breaking Space (U+00A0)",
    '\u202F': "Narrow No-Break Space (U+202F)",

    # Other Fixed-Width or Special Spaces
    '\u2000': "En Quad (U+2000)",
    '\u2001': "Em Quad (U+2001)",
    '\u2002': "En Space (U+2002)",
    '\u2003': "Em Space (U+2003)",
    '\u2004': "Three-Per-Em Space (U+2004)",
    '\u2005': "Four-Per-Em Space (U+2005)",
    '\u2006': "Six-Per-Em Space (U+2006)",
    '\u2007': "Figure Space (U+2007)",
    '\u2008': "Punctuation Space (U+2008)",
    '\u2009': "Thin Space (U+2009)",
    '\u200A': "Hair Space (U+200A)",
    '\u205F': "Medium Mathematical Space (U+205F)",
    '\u3000': "Ideographic Space (U+3000)",

    # Other Invisible or Control-like Characters
    '\u180E': "Mongolian Vowel Separator (U+180E)",
    '\u034F': "Combining Grapheme Joiner (U+034F)",
    '\u00AD': "Soft Hyphen (U+00AD)",

    # Directional Formatting Characters
    '\u200E': "Left-to-Right Mark",
    '\u200F': "Right-to-Left Mark",
    '\u202A': "Left-to-Right Embedding",
    '\u202B': "Right-to-Left Embedding",
    '\u202C': "Pop Directional Formatting",
    '\u202D': "Left-to-Right Override",
    '\u202E': "Right-to-Left Override",
    '\u2061': "Function Application",
    '\u2062': "Invisible Times",
    '\u2063': "Invisible Separator",
    '\u2064': "Invisible Plus",
    '\u2066': "Left-to-Right Isolate",
    '\u2067': "Right-to-Left Isolate",
    '\u2068': "First Strong Isolate",
    '\u2069': "Pop Directional Isolate",

    # Variation Selectors
    '\uFE00': "Variation Selector-1 (U+FE00)",
    '\uFE01': "Variation Selector-2 (U+FE01)",
    '\uFE02': "Variation Selector-3 (U+FE02)",
    '\uFE03': "Variation Selector-4 (U+FE03)",
    '\uFE04': "Variation Selector-5 (U+FE04)",
    '\uFE05': "Variation Selector-6 (U+FE05)",
    '\uFE06': "Variation Selector-7 (U+FE06)",
    '\uFE07': "Variation Selector-8 (U+FE07)",
    '\uFE08': "Variation Selector-9 (U+FE08)",
    '\uFE09': "Variation Selector-10 (U+FE09)",
    '\uFE0A': "Variation Selector-11 (U+FE0A)",
    '\uFE0B': "Variation Selector-12 (U+FE0B)",
    '\uFE0C': "Variation Selector-13 (U+FE0C)",
    '\uFE0D': "Variation Selector-14 (U+FE0D)",
    '\uFE0E': "Variation Selector-15 (U+FE0E)",
    '\uFE0F': "Variation Selector-16 (U+FE0F)",

    # Mongolian Free Variation Selectors
    '\u180B': "Mongolian Free Variation Selector One (FVS1, U+180B)",
    '\u180C': "Mongolian Free Variation Selector Two (FVS2, U+180C)",
    '\u180D': "Mongolian Free Variation Selector Three (FVS3, U+180D)",
}

# Typographic characters whose usage might be of interest
TYPOGRAPHIC_MARKERS: Dict[str, str] = {
    '\u2010': "Hyphen (U+2010)",
    '\u2013': "En Dash (U+2013)",
    '\u2014': "Em Dash (U+2014)",
    '\u2026': "Horizontal Ellipsis (U+2026)",
    # Smart Quotes / Curly Quotes
    '\u2018': "Left Single Quotation Mark (U+2018)",
    '\u2019': "Right Single Quotation Mark (U+2019)",
    '\u201C': "Left Double Quotation Mark (U+201C)",
    '\u201D': "Right Double Quotation Mark (U+201D)",
}

# The key is the character to be replaced, the value is its "correct" counterpart.
# This is ONLY active if typographic checks are enabled (default) AND --clean is used.
# If a character is in TYPOGRAPHIC_MARKERS but not here, it will only be detected, not replaced.
#
# These defaults aim to normalize various dashes to hyphen-minus and smart quotes to straight quotes,
# which is often preferred in programming contexts.
TYPOGRAPHIC_REPLACEMENTS: Dict[str, str] = {
    # Smart Quotes to Straight Quotes
    '\u2018': "'",  # Left Single Quotation Mark to Apostrophe (Straight Single Quote)
    '\u2019': "'",  # Right Single Quotation Mark to Apostrophe (Straight Single Quote)
    '\u201C': '"',  # Left Double Quotation Mark to Quotation Mark (Straight Double Quote)
    '\u201D': '"',  # Right Double Quotation Mark to Quotation Mark (Straight Double Quote)

    # Dashes to Hyphen-Minus (common in code/plain text contexts)
    # U+002D (Hyphen-Minus) is the target, so it's not a key here.
    '\u2010': '\u002D',  # Dedicated Hyphen to Hyphen-Minus
    '\u2013': '\u002D',  # En Dash to Hyphen-Minus
    '\u2014': '\u002D',  # Em Dash to Hyphen-Minus

    # Horizontal Ellipsis (U+2026) is in TYPOGRAPHIC_MARKERS for detection.
    # Replacing "..." with U+2026 or vice-versa is not a 1-to-1 char replacement
    # and would require a different mechanism (e.g., regex line processing).
    # So, no default replacement rule for U+2026 here.
}

# Ideographic Variation Selectors
IDEOGRAPHIC_VS_MARKERS: Dict[str, str] = {
    chr(i): f"Ideographic Variation Selector-{17 + (i - 0xE0100)} (VS{17 + (i - 0xE0100)}, U+{i:05X})"
    for i in range(0xE0100, 0xE01EF + 1)
}


MARKER_CHARS_HIDDEN: Set[str] = set(HIDDEN_MARKERS.keys())
MARKER_CHARS_TYPOGRAPHIC: Set[str] = set(TYPOGRAPHIC_MARKERS.keys())
MARKER_CHARS_IDEOGRAPHIC_VS: Set[str] = set(IDEOGRAPHIC_VS_MARKERS.keys())


# --- Logging Setup ---
class SimpleLogger:
    """Simplified logger with color support and minimal configuration."""

    # ANSI color codes
    COLORS = {
        'red': "\x1b[31;1m",
        'green': "\x1b[32;1m",
        'yellow': "\x1b[33;1m",
        'blue': "\x1b[34;1m",
        'magenta': "\x1b[35;1m",
        'cyan': "\x1b[36;1m",
        'reset': "\x1b[0m"
    }

    # Log levels
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40

    def __init__(self, level=INFO, use_colors=True, log_file=None):
        self.level = level
        self.use_colors = use_colors and sys.stdout.isatty()
        self.log_file = log_file
        self.file_handler = None

        if log_file:
            self.file_handler = open(log_file, 'w', encoding='utf-8')

    def _log(self, level, msg, *args, color=None):
        """Internal logging method."""
        if level < self.level:
            return

        # Format message with args if provided
        if args:
            msg = msg % args

        # Add color if enabled and color is specified
        if self.use_colors and color and color in self.COLORS:
            msg = f"{self.COLORS[color]}{msg}{self.COLORS['reset']}"

        # Write to stdout
        print(msg)

        # Write to file if configured (without colors)
        if self.file_handler:
            # Strip ANSI color codes for file output
            clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            self.file_handler.write(f"{clean_msg}\n")
            self.file_handler.flush()

    def debug(self, msg, *args):
        """Log a debug message."""
        self._log(self.DEBUG, msg, *args, color='cyan')

    def info(self, msg, *args):
        """Log an info message."""
        self._log(self.INFO, msg, *args)

    def warning(self, msg, *args):
        """Log a warning message."""
        self._log(self.WARNING, msg, *args, color='yellow')

    def error(self, msg, *args):
        """Log an error message."""
        self._log(self.ERROR, msg, *args, color='red')

    # Color convenience methods
    def red(self, msg):
        """Return text colored in red (if colors enabled)."""
        if not self.use_colors:
            return msg
        return f"{self.COLORS['red']}{msg}{self.COLORS['reset']}"

    def green(self, msg):
        """Return text colored in green (if colors enabled)."""
        if not self.use_colors:
            return msg
        return f"{self.COLORS['green']}{msg}{self.COLORS['reset']}"

    def yellow(self, msg):
        """Return text colored in yellow (if colors enabled)."""
        if not self.use_colors:
            return msg
        return f"{self.COLORS['yellow']}{msg}{self.COLORS['reset']}"

    def blue(self, msg):
        """Return text colored in blue (if colors enabled)."""
        if not self.use_colors:
            return msg
        return f"{self.COLORS['blue']}{msg}{self.COLORS['reset']}"

    def magenta(self, msg):
        """Return text colored in magenta (if colors enabled)."""
        if not self.use_colors:
            return msg
        return f"{self.COLORS['magenta']}{msg}{self.COLORS['reset']}"

    def cyan(self, msg):
        """Return text colored in cyan (if colors enabled)."""
        if not self.use_colors:
            return msg
        return f"{self.COLORS['cyan']}{msg}{self.COLORS['reset']}"

    def close(self):
        """Close file handler if it exists."""
        if self.file_handler:
            self.file_handler.close()
            self.file_handler = None

# Global logger instance, will be initialized in main()
log = None


# --- Data Models ---
@dataclass
class MarkerReport:
    """Represents a detected marker in a file."""
    char_idx: int
    original_char: str
    description: str
    marker_type: str
    action: str
    replacement: Optional[str] = None

@dataclass
class FileProcessResult:
    """Result of processing a file."""
    filepath: str
    had_marker_or_change: bool
    temp_file_path: Optional[str] = None
    error: Optional[str] = None
    detected_markers: int = 0
    processed_markers: int = 0

@dataclass
class ScanStats:
    """Statistics for the scan operation."""
    files_processed: int = 0
    files_with_markers: int = 0
    total_markers_detected: int = 0
    total_markers_processed: int = 0
    start_time: float = 0
    end_time: float = 0

    @property
    def elapsed_time(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0

    def update_from_result(self, result: FileProcessResult) -> None:
        self.files_processed += 1
        if result.had_marker_or_change:
            self.files_with_markers += 1
        self.total_markers_detected += result.detected_markers
        self.total_markers_processed += result.processed_markers

# --- File Processing Functions ---
def is_likely_text_file(filepath: str, chunk_size: int = 4096) -> bool:
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(chunk_size)
        if b'\x00' in chunk: # Null byte usually means binary
            return False
        # Try to decode a chunk as UTF-8. If it fails, it might be another encoding,
        # but for this basic check, we're primarily interested in avoiding true binary files.
        try:
            chunk.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            # Could be another text encoding, or binary that happens to not have nulls.
            # For this simple check, we'll lean towards 'text' if no nulls.
            pass # Potentially still text, just not UTF-8
        return True
    except (IOError, PermissionError):
        return False

def detect_file_encoding(filepath: str, fallback_encoding: str = 'utf-8') -> str:
    """
    Attempt to detect the encoding of a file.

    Args:
        filepath: Path to the file
        fallback_encoding: Encoding to use if detection fails

    Returns:
        Detected encoding or fallback
    """
    encodings_to_try = ['utf-8', 'latin-1', 'cp1252', sys.getdefaultencoding()]

    for encoding in encodings_to_try:
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                f.read(1024)  # Read a chunk to test encoding
                log.debug("Detected encoding for %s: %s", filepath, encoding)
                return encoding
        except UnicodeDecodeError:
            continue

    log.debug("Could not detect encoding for %s, using fallback: %s", filepath, fallback_encoding)
    return fallback_encoding

def process_line(
    line_text: str,
    line_num: int,
    clean_file: bool,
    check_typographic: bool,
    check_ivs: bool,
    user_excluded_chars: Set[str],
) -> Tuple[str, List[MarkerReport], bool]:
    """
    Process a single line of text, detecting and optionally replacing markers.

    Args:
        line_text: The line to process
        line_num: Line number (for reporting)
        clean_file: Whether to clean/replace markers
        check_typographic: Whether to check for typographic markers
        check_ivs: Whether to check for ideographic variation selectors
        user_excluded_chars: Set of characters to exclude from processing

    Returns:
        Tuple of (processed_line, marker_reports, line_changed)
    """
    processed_line_chars = list(line_text)
    reports: List[MarkerReport] = []
    line_changed = False

    # Process characters in the line
    for char_idx, original_char in enumerate(line_text):
        if original_char in user_excluded_chars:
            continue

        char_to_write = original_char
        report = None

        # Check for hidden markers
        if original_char in MARKER_CHARS_HIDDEN:
            is_bom = (line_num == 1 and char_idx == 0 and original_char == '\uFEFF')
            desc = HIDDEN_MARKERS[original_char]

            if not (is_bom and not clean_file):
                if clean_file:
                    action = "Removed" if not is_bom else "Processed (BOM)"
                    report = MarkerReport(char_idx, original_char, desc, "Hidden", action)
                    char_to_write = ""
                    line_changed = True
                else:
                    report = MarkerReport(char_idx, original_char, desc, "Hidden", "Detected")

        # Check for ideographic variation selectors
        elif check_ivs and original_char in MARKER_CHARS_IDEOGRAPHIC_VS:
            desc = IDEOGRAPHIC_VS_MARKERS[original_char]
            if clean_file:
                report = MarkerReport(char_idx, original_char, desc, "IdeographicVS", "Removed")
                char_to_write = ""
                line_changed = True
            else:
                report = MarkerReport(char_idx, original_char, desc, "IdeographicVS", "Detected")

        # Check for typographic markers
        elif check_typographic and original_char in MARKER_CHARS_TYPOGRAPHIC:
            desc = TYPOGRAPHIC_MARKERS[original_char]
            if clean_file and original_char in TYPOGRAPHIC_REPLACEMENTS:
                repl = TYPOGRAPHIC_REPLACEMENTS[original_char]
                if repl != original_char:
                    report = MarkerReport(char_idx, original_char, desc, "Typographic", "Replaced", repl)
                    char_to_write = repl
                    line_changed = True
                else:
                    report = MarkerReport(char_idx, original_char, desc, "Typographic", "Detected (Rule: no change)")
            else:
                report = MarkerReport(char_idx, original_char, desc, "Typographic", "Detected")

        if report:
            reports.append(report)

        processed_line_chars[char_idx] = char_to_write

    processed_line = "".join(processed_line_chars)
    return processed_line, reports, line_changed

def process_file(
    filepath: str,
    clean_file: bool,
    check_typographic: bool,
    check_ivs: bool,
    user_excluded_chars: Set[str],
    report_mode: str = "normal",
) -> FileProcessResult:
    """
    Process a file, detecting and optionally cleaning markers.

    Args:
        filepath: Path to the file
        clean_file: Whether to clean markers
        check_typographic: Whether to check for typographic markers
        check_ivs: Whether to check for ideographic variation selectors
        user_excluded_chars: Set of characters to exclude from processing
        report_mode: Reporting mode (normal, quiet, or verbose)

    Returns:
        FileProcessResult object with processing results
    """
    file_had_marker_or_change = False
    content_changed = False
    temp_file_path = None
    output_f = None
    detected_count = 0
    processed_count = 0

    try:
        # Determine file encoding
        encoding = detect_file_encoding(filepath)

        # Create temporary file if cleaning
        if clean_file:
            file_dir = os.path.dirname(filepath) or '.'
            try:
                output_temp_f_obj = tempfile.NamedTemporaryFile(
                    mode='w',
                    encoding='utf-8',
                    dir=file_dir,
                    delete=False,
                    prefix=f"tmp_{os.path.basename(filepath)}_"
                )
                temp_file_path = output_temp_f_obj.name
                output_f = output_temp_f_obj
                log.debug("Created temporary file %s for %s", temp_file_path, filepath)
            except Exception as e:
                error_msg = f"Could not create temporary file in {file_dir}: {e}"
                log.error(error_msg)
                return FileProcessResult(filepath, False, None, error_msg)

        # Process the file line by line
        line_reports = {}  # Store reports by line

        with open(filepath, 'r', encoding=encoding, errors='replace') as input_f:
            for i, line_text in enumerate(input_f):
                line_num = i + 1

                processed_line, reports, line_changed = process_line(
                    line_text,
                    line_num,
                    clean_file,
                    check_typographic,
                    check_ivs,
                    user_excluded_chars
                )

                if reports:
                    detected_count += len(reports)
                    file_had_marker_or_change = True
                    line_reports[line_num] = (line_text, processed_line, reports)

                # Write to temp file if cleaning
                if output_f:
                    output_f.write(processed_line)
                    if line_changed:
                        processed_count += len(reports)
                        content_changed = True

        # Close the temp file if opened
        if output_f:
            output_f.close()

        # Log report if markers were found
        if file_had_marker_or_change and report_mode != "quiet":
            log.info("\n%s %s", log.blue("File:"), filepath)

            for line_num, (original, modified, reports) in sorted(line_reports.items()):
                output_modified = modified != original

                log.info("  %s: Original: %s", log.cyan(f"L{line_num}"), original.rstrip())
                if output_modified:
                    log.info("  %s: %s %s",
                            log.cyan(f"L{line_num}"),
                            log.cyan("Modified:"),
                            modified.rstrip())

                for report in reports:
                    # Set colors based on action and marker type
                    if report.action == "Removed":
                        action_colored = log.red(report.action)
                    elif report.action == "Replaced" or report.action.startswith("Processed"):
                        action_colored = log.magenta(report.action)
                    else:
                        action_colored = log.yellow(report.action)

                    # Color marker type
                    if report.marker_type in ("Hidden", "IdeographicVS"):
                        type_colored = log.red(report.marker_type)
                    else:
                        type_colored = log.yellow(report.marker_type)

                    details = f"'{repr(report.original_char)}' ({report.description})"
                    if report.replacement:
                        details += f" -> '{repr(report.replacement)}'"

                    column_str = f"column {report.char_idx + 1}"
                    log.info("    %s (%s): %s at %s",
                            action_colored,
                            type_colored,
                            details,
                            log.cyan(column_str))

        # If cleaning but no changes made, clean up temp file
        if temp_file_path and not content_changed:
            try:
                os.remove(temp_file_path)
                temp_file_path = None
                log.debug("Removed unused temporary file for %s as no changes were made", filepath)
            except OSError as e:
                log.debug("Could not remove temporary file %s: %s", temp_file_path, e)

        return FileProcessResult(
            filepath=filepath,
            had_marker_or_change=file_had_marker_or_change,
            temp_file_path=temp_file_path if content_changed else None,
            detected_markers=detected_count,
            processed_markers=processed_count
        )

    except FileNotFoundError:
        log.error("File not found: %s", filepath)
        return FileProcessResult(filepath, False, None, "File not found")
    except PermissionError:
        log.error("Permission denied for file: %s", filepath)
        return FileProcessResult(filepath, False, None, "Permission denied")
    except Exception as e:
        log.error("Unexpected error processing %s: %s", filepath, str(e))
        return FileProcessResult(filepath, False, None, f"Unexpected error: {str(e)}")

# --- File Discovery Functions ---
def find_files_to_process(
    file_path: Optional[str],
    dir_path: Optional[str],
    recursive: bool,
    ignored_dir_names: Set[str],
    file_patterns: Optional[List[str]],
) -> List[str]:
    """
    Find files to process based on input parameters.

    Args:
        file_path: Path to a single file (or None)
        dir_path: Path to a directory (or None)
        recursive: Whether to recursively search directories
        ignored_dir_names: Set of directory names to ignore
        file_patterns: Optional list of file patterns to include

    Returns:
        List of file paths to process
    """
    files_to_process = []

    # Compile file pattern regex if specified
    pattern_regex = None
    if file_patterns:
        pattern_parts = []
        for pattern in file_patterns:
            # Convert glob-like patterns to regex
            regex_pattern = pattern.replace('.', '\\.').replace('*', '.*').replace('?', '.')
            pattern_parts.append(f"({regex_pattern})")
        pattern_regex = re.compile(f"^{'|'.join(pattern_parts)}$")
        log.debug("Using file pattern regex: %s", pattern_regex.pattern)

    # Process single file
    if file_path:
        if not os.path.isfile(file_path):
            log.error("File '%s' not found.", file_path)
            return []

        if is_likely_text_file(file_path):
            files_to_process.append(file_path)
            log.debug("Added file to process: %s", file_path)
        else:
            log.info("Skipping '%s' as it does not appear to be text.", file_path)

    # Process directory
    elif dir_path:
        if not os.path.isdir(dir_path):
            log.error("Directory '%s' not found.", dir_path)
            return []

        log.debug("Processing directory: %s (recursive=%s)", dir_path, recursive)

        if recursive:
            for root_dir, dirs_in_root, filenames_in_dir in os.walk(dir_path, topdown=True):
                # Filter out ignored directories
                original_dirs = set(dirs_in_root)
                dirs_in_root[:] = [d for d in dirs_in_root if d not in ignored_dir_names]

                # Log ignored directories if any were filtered
                ignored = original_dirs - set(dirs_in_root)
                if ignored and log.level <= log.DEBUG:
                    log.debug("Ignoring directories in %s: %s", root_dir, ", ".join(ignored))

                # Process files in current directory
                for filename in filenames_in_dir:
                    filepath = os.path.join(root_dir, filename)

                    # Apply file pattern filter if specified
                    if pattern_regex and not pattern_regex.match(filename):
                        log.debug("Skipping '%s' - doesn't match pattern.", filepath)
                        continue

                    if os.path.isfile(filepath) and is_likely_text_file(filepath):
                        files_to_process.append(filepath)
                        log.debug("Added file to process: %s", filepath)
        else:
            # Non-recursive directory scan
            for item in os.listdir(dir_path):
                filepath = os.path.join(dir_path, item)

                # Apply file pattern filter if specified
                if pattern_regex and not pattern_regex.match(item):
                    log.debug("Skipping '%s' - doesn't match pattern.", filepath)
                    continue

                if os.path.isfile(filepath) and is_likely_text_file(filepath):
                    files_to_process.append(filepath)
                    log.debug("Added file to process: %s", filepath)

    log.debug("Found %d files to process", len(files_to_process))
    return files_to_process

# --- Report Generation Functions ---
def display_summary_report(
    stats: ScanStats,
    report_mode: str = "normal"
) -> None:
    """
    Display a summary report of the scan results.

    Args:
        stats: ScanStats object with scan statistics
        report_mode: Reporting mode (normal, quiet, or verbose)
    """
    if report_mode == "quiet":
        return

    separator = "=" * 60
    log.info("\n%s", separator)
    log.info("%s", log.blue("SCAN SUMMARY"))
    log.info("%s", separator)
    log.info("Files processed: %d", stats.files_processed)
    log.info("Files with markers: %d", stats.files_with_markers)
    log.info("Total markers detected: %d", stats.total_markers_detected)

    if stats.total_markers_processed > 0:
        log.info("Total markers processed: %d", stats.total_markers_processed)

    log.info("Elapsed time: %.2f seconds", stats.elapsed_time)
    log.info("%s", separator)

    if stats.files_with_markers > 0:
        log.info("\nStatus: %s", log.yellow("MARKERS FOUND"))
    else:
        log.info("\nStatus: %s", log.green("NO MARKERS FOUND"))


def main():
    # --- Argument Parsing ---
    # (Epilog and examples remain the same, using f-strings as before)
    hidden_marker_examples = "\n".join([f"  '{m}' : {d}" for m, d in list(HIDDEN_MARKERS.items())[:8]])
    typo_marker_list = list(TYPOGRAPHIC_MARKERS.items())
    typo_marker_examples = "\n".join([f"  '{m}' : {d}" for m, d in typo_marker_list])
    typo_replacement_examples = "\n".join([f"  '{k}' -> '{v}' ({TYPOGRAPHIC_MARKERS.get(k, 'N/A')} to {TYPOGRAPHIC_MARKERS.get(v, 'N/A')})" for k,v in TYPOGRAPHIC_REPLACEMENTS.items()])
    if not typo_replacement_examples: typo_replacement_examples = "  (No rules defined in TYPOGRAPHIC_REPLACEMENTS)"
    ivs_example_start_char, ivs_example_start_desc = list(IDEOGRAPHIC_VS_MARKERS.items())[0] if IDEOGRAPHIC_VS_MARKERS else ("U+E0100", "IVS-17")
    ivs_example_end_char, ivs_example_end_desc = list(IDEOGRAPHIC_VS_MARKERS.items())[-1] if IDEOGRAPHIC_VS_MARKERS else ("U+E01EF", "IVS-256")

    parser = argparse.ArgumentParser(
        description="Search for watermarks, hidden, typographic, and IVS markers in text files.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s -f myfile.txt
  %(prog)s -f myfile.txt --check-typographic --exclude-char U+2013 --no-color
  %(prog)s -d project/ -r --ignore-dir .git -c -y
  %(prog)s -d docs/ -r -c --check-typographic --check-ivs

Detected by Default:
  - Hidden Markers: Removed by -c.
    Examples: {hidden_marker_examples} ...

Optional Checks:
  --check-typographic : Enables check for Typographic Markers.
    Examples: {typo_marker_examples}
  --check-ivs : Enables check for Ideographic Variation Selectors (VS17-VS256).
    Example Range: '{ivs_example_start_char}' ({ivs_example_start_desc}) to '{ivs_example_end_char}' ({ivs_example_end_desc})
    IVS are REMOVED if --clean and --check-ivs are active.

Typographic Replacements (active if -c AND --check-typographic are used):
{typo_replacement_examples}
  Edit TYPOGRAPHIC_REPLACEMENTS in script to customize.

Output Coloring: Use --no-color to disable. Respects NO_COLOR env var.
"""
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-f", "--file", help="Path to a single file to check.")
    input_group.add_argument("-d", "--dir", help="Path to a directory to check.")
    input_group.add_argument("--stdin", action="store_true", help="Read from standard input.")

    parser.add_argument("-r", "--recursive", action="store_true",
                      help="Recursively search in subdirectories (used with -d/--dir).")

    parser.add_argument("--ignore-dir", action="append", dest="ignored_dirs",
                      default=[], metavar="DIRNAME",
                      help="Directory name(s) to ignore during recursive scan (e.g., .git). Can be used multiple times.")

    parser.add_argument("--pattern", action="append", dest="file_patterns",
                      default=[], metavar="PATTERN",
                      help="File pattern(s) to include (e.g., *.py). Can be used multiple times.")

    parser.add_argument("-c", "--clean", action="store_true",
                      help="Automatically clean/replace detected markers. Warning: This modifies files in place!")

    parser.add_argument("-y", "--yes", action="store_true", dest="auto_confirm_clean",
                      help="Automatically confirm 'yes' to prompts when cleaning files. Use with caution.")

    parser.add_argument("--exclude-char", action="append", dest="excluded_chars_str",
                      default=[], metavar="U+XXXX or Char",
                      help="Unicode character(s) to exclude from detection/cleaning. Can be used multiple times.")

    parser.add_argument("--fail", action="store_true",
                      help="Exit with status code 1 if any specified markers are detected/changed.")

    parser.add_argument("--check-typographic", action="store_true",
                      help="Enable the check for specified typographic markers (disabled by default).")

    parser.add_argument("--check-ivs", action="store_true",
                      help="Enable the check for Ideographic Variation Selectors (VS17-VS256).")

    parser.add_argument("--no-color", action="store_true",
                      help="Disable colored output.")

    parser.add_argument("--report-file", metavar="FILE",
                      help="Write detailed report to a file.")

    parser.add_argument("--report-mode", choices=["normal", "quiet", "verbose"],
                      default="normal", help="Set the level of reporting detail.")

    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                      default="INFO", help="Set the logging level.")

    parser.add_argument("--log-file", metavar="FILE",
                      help="Write logs to a file instead of stdout.")

    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    # --- Set up logging ---
    use_colors = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and not args.no_color

    # Set up the global logger
    global log

    # Map log levels from strings to integers
    log_levels = {
        "DEBUG": SimpleLogger.DEBUG,
        "INFO": SimpleLogger.INFO,
        "WARNING": SimpleLogger.WARNING,
        "ERROR": SimpleLogger.ERROR
    }

    log = SimpleLogger(
        level=log_levels[args.log_level],
        use_colors=use_colors,
        log_file=args.log_file
    )

    log.debug("Starting Unicode Marker Detector v%s", VERSION)
    log.debug("Log level set to %s", args.log_level)

    # Process excluded characters
    user_excluded_chars: Set[str] = set()
    for char_str in args.excluded_chars_str:
        parsed_char = None
        try:
            hex_code = char_str
            if hex_code.startswith('U+') and len(hex_code) > 2:
                hex_code = hex_code[2:]
            if (4 <= len(hex_code) <= 6) and hex_code.isalnum():
                parsed_char = chr(int(hex_code.upper(), 16))
            elif len(char_str) == 1: # Treat as a literal character
                parsed_char =  char_str
        finally:
            if parsed_char:
                user_excluded_chars.add(parsed_char)
                log.debug(f"Excluding character: '{repr(parsed_char)}' (U+{ord(parsed_char):04X})")
            else:
                log.error("\n%s for --exclude-char '%s'. Use U+XXXX, plain char, or hex.", log.red("Error: Invalid format"), char_str)
                raise SystemExit(1)

    # Override clean flag if dry-run is specified
    clean_file = args.clean

    # --- Find files to process ---
    ignored_dir_names = set(args.ignored_dirs) if args.ignored_dirs else set()
    if ignored_dir_names:
        log.debug("Ignored directories: %s", ", ".join(ignored_dir_names))

    # For stdin mode, create a temporary file
    stdin_temp_file = None
    if args.stdin:
        log.debug("Reading from standard input")
        try:
            stdin_data = sys.stdin.read()
            stdin_temp_file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False)
            stdin_temp_file.write(stdin_data)
            stdin_temp_file.close()
            files_to_process = [stdin_temp_file.name]
            log.debug("Created temporary file from stdin: %s", stdin_temp_file.name)
        except Exception as e:
            log.error("Error reading from stdin: %s", e)
            raise SystemExit(1)
    else:
        files_to_process = find_files_to_process(
            args.file,
            args.dir,
            args.recursive,
            ignored_dir_names,
            args.file_patterns
        )

    if not files_to_process:
        log.warning("No text files found or selected for processing.")
        raise SystemExit(1)

    # --- Process files ---
    stats = ScanStats()
    stats.start_time = time.time()

    # Create shared configuration for worker processes
    worker_config = {
        'clean_file': clean_file,
        'check_typographic': args.check_typographic,
        'check_ivs': args.check_ivs,
        'user_excluded_chars': user_excluded_chars,
        'report_mode': args.report_mode
    }

    # Map of original file paths to temp file paths for changed files
    files_to_commit = {}

    log.info(f"Starting scan of {len(files_to_process)} file(s)...")

    for filepath in files_to_process:
        try:
            result = process_file(
                filepath,
                clean_file,
                args.check_typographic,
                args.check_ivs,
                user_excluded_chars,
                args.report_mode
            )

            stats.update_from_result(result)
            if result.error:
                log.error(f"Error processing {result.filepath}: {result.error}")
            if result.temp_file_path:
                files_to_commit[result.filepath] = result.temp_file_path
                log.debug(f"Added file to commit: {result.filepath} -> {result.temp_file_path}")
        except KeyboardInterrupt:
            log.warning("Processing interrupted by user")
            raise SystemExit(1)

    stats.end_time = time.time()

    # --- Cleanup for stdin mode ---
    if args.stdin and stdin_temp_file:
        if stdin_temp_file.name in files_to_commit:
            log.debug("Processing cleaned stdin content")
            # Write cleaned content to stdout
            try:
                with open(files_to_commit[stdin_temp_file.name], 'r', encoding='utf-8') as f:
                    cleaned_content = f.read()
                    sys.stdout.write(cleaned_content)
                # Remove the temp file
                os.remove(files_to_commit[stdin_temp_file.name])
                log.debug(f"Removed temporary output file: {files_to_commit[stdin_temp_file.name]}")
                del files_to_commit[stdin_temp_file.name]
            except Exception as e:
                log.error(f"Error processing cleaned stdin content: {e}")

        # Remove the input temp file
        try:
            os.remove(stdin_temp_file.name)
            log.debug(f"Removed temporary stdin file: {stdin_temp_file.name}")
        except OSError as e:
            log.error(f"Error removing temporary stdin file: {e}")

    # --- Confirmation and commit phase ---
    commit_changes = False
    temp_files_to_remove = list(files_to_commit.values())

    if clean_file and files_to_commit:
        log.warning(f"\nModifications generated for {len(files_to_commit)} file(s).")

        if not args.auto_confirm_clean:
            try:
                confirm = input("Save changes? (yes/no): ").lower().strip()
                if confirm == 'yes':
                    commit_changes = True
                    log.info("User confirmed changes")
                else:
                    log.info("Changes discarded by user")
            except (EOFError, KeyboardInterrupt):
                log.error("\nNon-interactive environment detected. Discarding changes.")
                log.info("Use -y or --yes to save changes non-interactively.")
        else:
            log.warning("Applying changes automatically due to -y/--yes flag.")
            commit_changes = True

        if commit_changes:
            log.info("Saving modified files...")
            saved_count = 0
            commit_errors = 0

            for original_path, temp_path in list(files_to_commit.items()):
                try:
                    if os.path.exists(temp_path):
                        original_stat = os.stat(original_path)
                        os.replace(temp_path, original_path)
                        os.chmod(original_path, original_stat.st_mode)
                        saved_count += 1
                        temp_files_to_remove.remove(temp_path)
                        log.debug(f"Saved changes to {original_path}")
                    else:
                        log.error(f"Error saving {original_path}: Temporary file {temp_path} not found.")
                        commit_errors += 1
                except OSError as e:
                    log.error(f"Error saving changes for {original_path}: {e}")
                    commit_errors += 1

            log.info(f"Finished saving: {saved_count} file(s) updated successfully, {commit_errors} error(s).")

    # Clean up temporary files
    for temp_path in temp_files_to_remove:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                log.debug(f"Removed temporary file: {temp_path}")
            except OSError as e:
                log.error(f"Failed to remove temporary file {temp_path}: {e}")

    # --- Generate final report ---
    display_summary_report(stats, args.report_mode)

    # Write report to file if requested
    if args.report_file:
        try:
            with open(args.report_file, 'w', encoding='utf-8') as f:
                f.write(f"UNICODE MARKER DETECTOR REPORT\n")
                f.write(f"===========================\n\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Files processed: {stats.files_processed}\n")
                f.write(f"Files with markers: {stats.files_with_markers}\n")
                f.write(f"Total markers detected: {stats.total_markers_detected}\n")
                if stats.total_markers_processed > 0:
                    f.write(f"Total markers processed: {stats.total_markers_processed}\n")
                f.write(f"Elapsed time: {stats.elapsed_time:.2f} seconds\n\n")

                f.write(f"Status: {'MARKERS FOUND' if stats.files_with_markers > 0 else 'NO MARKERS FOUND'}\n")

            log.info(f"Report written to {args.report_file}")
        except Exception as e:
            log.error(f"Error writing report to {args.report_file}: {e}")

    # Determine exit code
    exit_code = 0
    if args.fail and stats.files_with_markers > 0:
        log.warning("Exiting with status 1 due to --fail flag and detected markers/changes.")
        exit_code = 1

    log.debug("Script execution completed")
    raise SystemExit(exit_code)

if __name__ == "__main__":
    main()