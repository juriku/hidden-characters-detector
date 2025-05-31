#!/usr/bin/env python3


import argparse
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

try:
    import emoji
    emoji_library_available = True
except ImportError:
    print(
        "The 'emoji' library is not installed. Emoji-specific checks will be skipped. "
        "Install it with 'pip install emoji' for full functionality.",
        ImportWarning
    )
    emoji_library_available = False

__all__ = [
    "SimpleLogger",
    "MarkerReport",
    "FileProcessResult",
    "ScanStats",
    "UnicodeMarkerDetector",
]

# --- Configuration ---
VERSION = "1.1.0"

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

    # Hyphens/Dashes
    '\u2010': "Hyphen (U+2010)",
    '\u2011': "Non-Breaking Hyphen (U+2011)",
    '\u2013': "En Dash (U+2013)",
    '\u2014': "Em Dash (U+2014)",
    '\u2012': "Figure Dash (U+2012)",
    '\u2015': "Horizontal Bar (U+2015)",
    '\u2212': "Minus Sign (U+2212)",
    '\uFE63': "Small Hyphen-Minus (U+FE63)",
    # '\u2026': "Horizontal Ellipsis (U+2026)",
    # '\u2022': "Bullet (U+2022)",

    # Smart Quotes / Curly Quotes
    # '\u2018': "Left Single Quotation Mark (U+2018)",
    # '\u2019': "Right Single Quotation Mark (U+2019)",
    # '\u201C': "Left Double Quotation Mark (U+201C)",
    # '\u201D': "Right Double Quotation Mark (U+201D)",

    # Periods / Dots
    '\u00B7': "Middle Dot (U+00B7)",
    '\u2219': "Bullet Operator (U+2219)",
    '\u2023': "Triangular Bullet (U+2023)",
    '\u2024': "One Dot Leader (U+2024)",
    '\u2025': "Two Dot Leader (U+2025)",
    '\u2027': "Hyphenation Point (U+2027)",
    '\u2059': "Tricolon (U+2059)",
    '\u3002': "Ideographic Full Stop (U+3002)",
    '\uFE52': "Small Full Stop (U+FE52)",
    '\u205A': "Four Dot Mark (U+205A)",

    # Additional Apostrophes/Quotes/Primes
    '\u00B4': "Acute Accent (U+00B4)",
    '\u02B9': "Modifier Letter Prime (U+02B9)",
    '\u02BB': "Modifier Letter Turned Comma (U+02BB)",
    '\u02BC': "Modifier Letter Apostrophe (U+02BC)",
    '\u02C8': "Modifier Letter Vertical Line (U+02C8)",
    '\u0301': "Combining Acute Accent (U+0301 - Use with space or letter)",

    # prime / quote-like marks
    '\u2032': "Prime (U+2032)",
    '\u2033': "Double Prime (U+2033)",
    '\u2034': "Triple Prime (U+2034)",
    '\u2035': "Reversed Prime (U+2035)",
    '\u2036': "Reversed Double Prime (U+2036)",

    # subtle markers
    '\u2052': "Commercial Minus (U+2052)",
    '\u02BE': "Modifier Letter Right Half Ring (U+02BE)",
    '\uFF0E': "Full-Width Full Stop (U+FF0E)",
    '\uFF0C': "Full-Width Comma (U+FF0C)",
    '\uFF07': "Fullwidth Apostrophe (U+FF07)",

    # Commas
    '\u060C': "Arabic Comma (U+060C)",
    '\u201A': "Single Low-9 Quotation Mark (U+201A)",
    '\uFE50': "Small Comma (U+FE50)",

    # Slashes
    '\u2044': "Fraction Slash (U+2044)",
    '\u2215': "Division Slash (U+2215)",
    '\uFF0F': "Fullwidth Solidus (U+FF0F)",

    # Exclamation Marks
    '\u01C3': "Latin Letter Retroflex Click (U+01C3)",
    '\uFF01': "Fullwidth Exclamation Mark (U+FF01)",

    # Question Marks
    '\u037E': "Greek Question Mark (U+037E)",
    '\uFF1F': "Fullwidth Question Mark (U+FF1F)",

    # Colons / Semicolons
    '\uFE55': "Small Colon (U+FE55)",
    '\uFE56': "Small Semicolon (U+FE56)",
    '\uFF1A': "Fullwidth Colon (U+FF1A)",
    '\uFF1B': "Fullwidth Semicolon (U+FF1B)",

    # Homoglyphs (Letters - Selected Pairs/Trios)
    '\u0391': "Greek Capital Letter Alpha (U+0391)",
    '\u0410': "Cyrillic Capital Letter A (U+0410)",
    '\u0421': "Cyrillic Capital Letter Es (U+0421)",
    '\u0395': "Greek Capital Letter Epsilon (U+0395)",
    '\u0415': "Cyrillic Capital Letter Ie (U+0415)",
    '\u0397': "Greek Capital Letter Eta (U+0397)",
    '\u041D': "Cyrillic Capital Letter En (U+041D)",
    '\u0399': "Greek Capital Letter Iota (U+0399)",
    '\u0406': "Cyrillic Capital Letter Byelorussian-Ukrainian I (U+0406)",
    '\u0408': "Cyrillic Capital Letter Je (U+0408)",
    '\u039A': "Greek Capital Letter Kappa (U+039A)",
    '\u039C': "Greek Capital Letter Mu (U+039C)",
    '\u041C': "Cyrillic Capital Letter Em (U+041C)",
    '\u039F': "Greek Capital Letter Omicron (U+039F)",
    '\u041E': "Cyrillic Capital Letter O (U+041E)",
    '\u03A1': "Greek Capital Letter Rho (U+03A1)",
    '\u0420': "Cyrillic Capital Letter Er (U+0420)",
    '\u0405': "Cyrillic Capital Letter Dze (U+0405)",
    '\u03A4': "Greek Capital Letter Tau (U+03A4)",
    '\u03A7': "Greek Capital Letter Chi (U+03A7)",
    '\u0425': "Cyrillic Capital Letter Ha (U+0425)",
    '\u03A5': "Greek Capital Letter Upsilon (U+03A5)",
    '\u0430': "Cyrillic Small Letter A (U+0430)",
    '\u0441': "Cyrillic Small Letter Es (U+0441)",
    '\u0435': "Cyrillic Small Letter Ie (U+0435)",
    '\u0456': "Cyrillic Small Letter Byelorussian-Ukrainian I (U+0456)",
    '\u0458': "Cyrillic Small Letter Je (U+0458)",
    '\u03BF': "Greek Small Letter Omicron (U+03BF)",
    '\u043E': "Cyrillic Small Letter O (U+043E)",
    '\u0440': "Cyrillic Small Letter Er (U+0440)",
    '\u0445': "Cyrillic Small Letter Ha (U+0445)",
    '\u0443': "Cyrillic Small Letter U (U+0443)",
}

# The key is the character to be replaced, the value is its "correct" counterpart.
# This is ONLY active if typographic checks are enabled (default) AND --clean is used.
# If a character is in TYPOGRAPHIC_MARKERS but not here, it will only be detected, not replaced.
#
# These defaults aim to normalize various dashes to hyphen-minus and smart quotes to straight quotes,
# which is often preferred in programming contexts.
TYPOGRAPHIC_REPLACEMENTS: Dict[str, str] = {
    # --- Standard Normalizations (Quotes & Dashes) ---
    # Smart Quotes to Straight Quotes
    # '\u2018': "'",  # Left Single Quotation Mark -> Apostrophe
    # '\u2019': "'",  # Right Single Quotation Mark -> Apostrophe
    # '\u201C': '"',  # Left Double Quotation Mark -> Quotation Mark
    # '\u201D': '"',  # Right Double Quotation Mark -> Quotation Mark

    # Dashes to Hyphen-Minus (U+002D)
    '\u2010': '\u002D',  # Hyphen -> Hyphen-Minus
    '\u2011': '\u002D',  # Non-Breaking Hyphen -> Hyphen-Minus
    '\u2013': '\u002D',  # En Dash -> Hyphen-Minus
    '\u2014': '\u002D',  # Em Dash -> Hyphen-Minus
    '\u2012': '\u002D',  # Figure Dash -> Hyphen-Minus
    '\u2015': '\u002D',  # Horizontal Bar -> Hyphen-Minus
    '\u2212': '\u002D',  # Minus Sign -> Hyphen-Minus
    '\uFE63': '\u002D',  # Small Hyphen-Minus -> Hyphen-Minus
    '\u2052': '\u002D',  # Commercial Minus -> Hyphen-Minus

    # --- Punctuation Normalizations ---
    # Ellipsis & Dots
    ## technically not one to one repalcement - for detection only
    # Horizontal Ellipsis (U+2026) is in TYPOGRAPHIC_MARKERS for detection.
    # Replacing "..." with U+2026 or vice-versa is not a 1-to-1 char replacement
    # So, no default replacement rule for U+2026 here.
    # '\u2026': '...', # Horizontal Ellipsis -> Three Dots
    '\u00B7': '.',  # Middle Dot -> Full Stop
    '\u2219': '.',  # Bullet Operator -> Full Stop
    '\u2023': '*',  # Triangular Bullet -> Asterisk (common fallback)
    '\u2024': '.',  # One Dot Leader -> Full Stop
    '\u2025': '..', # Two Dot Leader -> Two Dots
    '\u2027': '.',  # Hyphenation Point -> Full Stop
    '\u3002': '.',  # Ideographic Full Stop -> Full Stop
    '\uFE52': '.',  # Small Full Stop -> Full Stop
    '\uFF0E': '.',  # Full-Width Full Stop -> Full Stop
    # U+2059 (Tricolon) & U+205A (Four Dot Mark) are less common and often don't have a standard single replacement.

    # Additional Apostrophes/Quotes/Primes
    '\u00B4': "'",  # Acute Accent -> Apostrophe
    '\u02B9': "'",  # Modifier Letter Prime -> Apostrophe
    '\u02BB': "'",  # Modifier Letter Turned Comma -> Apostrophe
    '\u02BC': "'",  # Modifier Letter Apostrophe -> Apostrophe
    '\u02BE': "'",  # Modifier Letter Right Half Ring -> Apostrophe
    '\u2032': "'",  # Prime -> Apostrophe
    '\u2033': '"',  # Double Prime -> Quotation Mark
    '\u2035': "'",  # Reversed Prime -> Apostrophe
    '\u2036': '"',  # Reversed Double Prime -> Quotation Mark
    '\uFF07': "'",  # Fullwidth Apostrophe -> Apostrophe

    # Commas
    '\u060C': ',',  # Arabic Comma -> Comma
    '\u201A': ',',  # Single Low-9 Quotation Mark -> Comma (can also be a quote, but visually closer to comma)
    '\uFE50': ',',  # Small Comma -> Comma
    '\uFF0C': ',',  # Full-Width Comma -> Comma

    # Slashes
    '\u2044': '/',  # Fraction Slash -> Solidus
    '\u2215': '/',  # Division Slash -> Solidus
    '\uFF0F': '/',  # Fullwidth Solidus -> Solidus

    # Exclamation Marks
    '\u01C3': '!',  # Latin Letter Retroflex Click -> Exclamation Mark
    '\uFF01': '!',  # Fullwidth Exclamation Mark -> Exclamation Mark

    # Question Marks
    '\u037E': ';',  # Greek Question Mark -> Semicolon (Its actual equivalent)
    '\uFF1F': '?',  # Fullwidth Question Mark -> Question Mark

    # Colons / Semicolons
    '\uFE55': ':',  # Small Colon -> Colon
    '\uFE56': ';',  # Small Semicolon -> Semicolon
    '\uFF1A': ':',  # Fullwidth Colon -> Colon
    '\uFF1B': ';',  # Fullwidth Semicolon -> Semicolon

    # --- Homoglyph Normalizations (to Latin ASCII) ---
    # A
    '\u0391': 'A',  # Greek Alpha -> A
    '\u0410': 'A',  # Cyrillic A -> A
    # C
    '\u0421': 'C',  # Cyrillic Es -> C
    # E
    '\u0395': 'E',  # Greek Epsilon -> E
    '\u0415': 'E',  # Cyrillic Ie -> E
    # H
    '\u0397': 'H',  # Greek Eta -> H
    '\u041D': 'H',  # Cyrillic En -> H
    # I
    '\u0399': 'I',  # Greek Iota -> I
    '\u0406': 'I',  # Cyrillic I -> I
    # J
    '\u0408': 'J',  # Cyrillic Je -> J
    # K
    '\u039A': 'K',  # Greek Kappa -> K
    # M
    '\u039C': 'M',  # Greek Mu -> M
    '\u041C': 'M',  # Cyrillic Em -> M
    # O
    '\u039F': 'O',  # Greek Omicron -> O
    '\u041E': 'O',  # Cyrillic O -> O
    # P
    '\u03A1': 'P',  # Greek Rho -> P
    '\u0420': 'P',  # Cyrillic Er -> P
    # S
    '\u0405': 'S',  # Cyrillic Dze -> S
    # T
    '\u03A4': 'T',  # Greek Tau -> T
    # X
    '\u03A7': 'X',  # Greek Chi -> X
    '\u0425': 'X',  # Cyrillic Ha -> X
    # Y
    '\u03A5': 'Y',  # Greek Upsilon -> Y
    # a
    '\u0430': 'a',  # Cyrillic a -> a
    # c
    '\u0441': 'c',  # Cyrillic es -> c
    # e
    '\u0435': 'e',  # Cyrillic ie -> e
    # i
    '\u0456': 'i',  # Cyrillic i -> i
    # j
    '\u0458': 'j',  # Cyrillic je -> j
    # o
    '\u03BF': 'o',  # Greek omicron -> o
    '\u043E': 'o',  # Cyrillic o -> o
    # p
    '\u0440': 'p',  # Cyrillic er -> p
    # x
    '\u0445': 'x',  # Cyrillic ha -> x
    # y
    '\u0443': 'y',  # Cyrillic u -> y (often used as a 'y' homoglyph)

    # --- Whitespace Normalizations ---
    # Replace various spaces with standard space (U+0020)
    '\u00A0': ' ',  # No-Break Space
    '\u2000': ' ',  # En Quad
    '\u2001': ' ',  # Em Quad
    '\u2002': ' ',  # En Space
    '\u2003': ' ',  # Em Space
    '\u2004': ' ',  # Three-Per-Em Space
    '\u2005': ' ',  # Four-Per-Em Space
    '\u2006': ' ',  # Six-Per-Em Space
    '\u2007': ' ',  # Figure Space
    '\u2008': ' ',  # Punctuation Space
    '\u2009': ' ',  # Thin Space
    '\u200A': ' ',  # Hair Space
    '\u202F': ' ',  # Narrow No-Break Space
    '\u3000': ' ',  # Ideographic Space

    # Replace zero-width spaces/characters with an empty string (remove them)
    '\u00AD': '',   # Soft Hyphen
    '\u200B': '',   # Zero Width Space
    '\u200C': '',   # Zero Width Non-Joiner
    '\u200D': '',   # Zero Width Joiner
    '\uFEFF': '',   # Zero Width No-Break Space / BOM
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
    COLORS: Dict[str, str] = {
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

    def __init__(
        self,
        level: int = INFO,
        use_colors: bool | None = None,
        log_file: Optional[str] = None,
    ) -> None:
        self.level = level
        self.use_colors = (
            sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
            if use_colors is None
            else bool(use_colors)
        )
        self.file_handler = (
            open(log_file, "w", encoding="utf-8") if log_file else None
        )

    def _log(self, level: int, msg: str, *args, color: Optional[str] = None) -> None:
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
            print(clean_msg, file=self.file_handler)
            self.file_handler.flush()

    def debug(self, msg: str, *args):
        self._log(self.DEBUG, msg, *args, color="cyan")

    def info(self, msg: str, *args):
        self._log(self.INFO, msg, *args)

    def warning(self, msg: str, *args):
        self._log(self.WARNING, msg, *args, color="yellow")

    def error(self, msg: str, *args):
        self._log(self.ERROR, msg, *args, color="red")

    # Color convenience methods
    def red(self, s: str) -> str:
        return self._colorize("red", s)

    def green(self, s: str) -> str:
        return self._colorize("green", s)

    def yellow(self, s: str) -> str:
        return self._colorize("yellow", s)

    def blue(self, s: str) -> str:
        return self._colorize("blue", s)

    def magenta(self, s: str) -> str:
        return self._colorize("magenta", s)

    def cyan(self, s: str) -> str:
        return self._colorize("cyan", s)

    def close(self):
        """Close file handler if it exists."""
        if self.file_handler:
            self.file_handler.close()
            self.file_handler = None

    # internal ----------------------------------------------------------
    def _colorize(self, color: str, s: str) -> str:
        return (
            f"{self.COLORS[color]}{s}{self.COLORS['reset']}" if self.use_colors else s
        )

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
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def elapsed_time(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0

    def update_from_result(self, result: FileProcessResult) -> None:
        self.files_processed += 1
        if result.had_marker_or_change:
            self.files_with_markers += 1
        self.total_markers_detected += result.detected_markers
        self.total_markers_processed += result.processed_markers


# ---------------------------------------------------------------------------
#  Core class
# ---------------------------------------------------------------------------
class UnicodeMarkerDetector:
    """Detect and optionally clean hidden/typographic/IVS markers."""

    # Expose version via class attribute for convenience
    VERSION = VERSION

    # ------------------------------------------------------------------
    def __init__(
        self,
        *,
        clean_file: bool = False,
        check_typographic: bool = False,
        check_ivs: bool = False,
        user_excluded_chars: Optional[Set[str]] = None,
        report_mode: str = "normal",
        logger: Optional[SimpleLogger] = None,
    ) -> None:
        self.clean_file = clean_file
        self.check_typographic = check_typographic
        self.check_ivs = check_ivs
        self.user_excluded_chars: Set[str] = set(user_excluded_chars or [])
        self.report_mode = report_mode  # normal | quiet | verbose
        self.multiple_files = False
        self.log = logger or SimpleLogger()
        self._results: Dict[str, FileProcessResult] = {}

    # ------------------------------------------------------------------
    #  Low-level helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_likely_text_file(path: str, chunk_size: int = 4096) -> bool:
        """Heuristic test: null-byte == binary; else assume text."""
        try:
            file_size = os.path.getsize(path)
            if file_size == 0:
                return True # Empty files are considered text
            chunk_to_read = min(chunk_size, file_size)
            with open(path, 'rb') as f:
                chunk = f.read(chunk_to_read)
            if b'\x00' in chunk: # Null byte usually means binary
                return False
            # Try to decode a chunk as UTF-8. If it fails, it might be another encoding,
            # but for this basic check, we're primarily interested in avoiding true binary files.
            try:
                chunk.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                # Check if it's likely another text encoding
                text_bytes = 0
                for byte in chunk:
                    if 32 <= byte <= 126 or byte in [9, 10, 13]:  # printable ASCII + common whitespace
                        text_bytes += 1
                # If more than 75% looks like text, consider it text
                if text_bytes / len(chunk) > 0.75:
                    return True
                return False
            return True
        except (IOError, PermissionError):
            return False

    def _detect_file_encoding(self, path: str, fallback: str = 'utf-8') -> str:
        """Attempt to detect the encoding of a file."""
        for enc in ['utf-8', 'utf-16', 'latin-1', 'cp1252', sys.getdefaultencoding()]:
            try:
                with open(path, 'r', encoding=enc) as f:
                    f.read(1024)  # Read a chunk to test encoding
                    self.log.debug("Detected encoding for %s: %s", path, enc)
                    return enc
            except UnicodeDecodeError:
                continue
        self.log.debug("Could not detect encoding for %s, using fallback: %s", path, fallback)
        return fallback

    # ------------------------------------------------------------------
    def _process_line(
        self,
        text: str,
        line_num: int,
    ) -> Tuple[str, List[MarkerReport], bool]:
        """Scan one line; return replaced line, list of marker reports, and flag."""
        processed_chars: List[str] = list(text)
        reports: List[MarkerReport] = []
        changed = False

        for idx, ch in enumerate(text):
            if ch in self.user_excluded_chars:
                continue
            replacement: Optional[str] = None
            report: Optional[MarkerReport] = None

            ## \uFE0F holds key mechanism for ensuring that common symbols are rendered as the popular emoji graphics
            if ch == '\uFE0F':
                if idx > 0:
                    if emoji_library_available:
                        sequence_to_check = text[idx-1:idx+1] # The potential emoji sequence
                        if emoji.is_emoji(sequence_to_check):
                            print(f"Emoji detected: {sequence_to_check} at index {idx} in line {line_num}")
                            continue

            # Check for hidden markers
            if ch in MARKER_CHARS_HIDDEN:
                is_bom = line_num == 1 and idx == 0 and ch == '\uFEFF'
                desc = HIDDEN_MARKERS[ch]
                if not (is_bom and not self.clean_file):
                    action = "Processed (BOM)" if is_bom and self.clean_file else (
                        "Removed" if self.clean_file else "Detected"
                    )
                    replacement = "" if self.clean_file else None
                    changed |= bool(replacement == "")
                    report = MarkerReport(idx, ch, desc, "Hidden", action)

            # Check for ideographic variation selectors
            elif self.check_ivs and ch in MARKER_CHARS_IDEOGRAPHIC_VS:
                desc = IDEOGRAPHIC_VS_MARKERS[ch]
                action = "Removed" if self.clean_file else "Detected"
                replacement = "" if self.clean_file else None
                changed |= bool(replacement == "")
                report = MarkerReport(idx, ch, desc, "IdeographicVS", action)

            # Check for typographic markers
            elif self.check_typographic and ch in MARKER_CHARS_TYPOGRAPHIC:
                desc = TYPOGRAPHIC_MARKERS[ch]
                if self.clean_file and ch in TYPOGRAPHIC_REPLACEMENTS:
                    replacement = TYPOGRAPHIC_REPLACEMENTS[ch]
                    action = "Replaced" if replacement != ch else "Detected (Rule: no change)"
                    changed |= replacement != ch
                else:
                    action = "Detected"
                report = MarkerReport(idx, ch, desc, "Typographic", action, replacement)

            if report:
                reports.append(report)
                processed_chars[idx] = replacement if replacement is not None else ch

        return "".join(processed_chars), reports, changed

    # ------------------------------------------------------------------
    def _process_file(self, filepath: str) -> FileProcessResult:
        """Process a file, detecting and optionally cleaning markers."""
        detected = processed = 0
        temp_path: Optional[str] = None
        content_changed = False
        had_marker = False

        try:
            encoding = self._detect_file_encoding(filepath)
            if self.clean_file:
                try:
                    temp_obj = tempfile.NamedTemporaryFile(
                        mode='w',
                        encoding='utf-8',
                        delete=False,
                        dir=os.path.dirname(filepath) or ".",
                        prefix=f"tmp_{os.path.basename(filepath)}_",
                    )
                    temp_path = temp_obj.name
                    out_f = temp_obj
                    self.log.debug("Created temporary file %s for %s", temp_path, filepath)
                except Exception as e_temp_file:
                    error_msg = f"Could not create temporary file: {e_temp_file}"
                    self.log.error(error_msg)
                    return FileProcessResult(filepath, False, None, error_msg)
            else:
                out_f = None

            line_reports: Dict[int, Tuple[str, str, List[MarkerReport]]] = {}
            with open(filepath, 'r', encoding=encoding, errors='replace') as in_f:
                for i, line in enumerate(in_f, start=1):
                    new_line, reports, changed = self._process_line(line, i)
                    if reports:
                        detected += len(reports)
                        had_marker = True
                        line_reports[i] = (line, new_line, reports)

                    # Write to temp file if cleaning
                    if out_f:
                        out_f.write(new_line)
                        if changed:
                            content_changed = True
                            processed += len(reports)

            # Close the temp file if opened
            if out_f:
                out_f.close()

            # Info / verbose reporting --------------------------------
            if had_marker and self.report_mode != "quiet":
                self._log_file_report(filepath, line_reports)

            # If cleaning but no changes made, clean up temp file
            if temp_path and not content_changed:
                try:
                    os.remove(temp_path)
                    temp_path = None
                    self.log.debug("Removed unused temporary file for %s as no changes were made", filepath)

                except OSError as e_temp_rm:
                    self.log.debug("Could not remove temporary file %s: %s", temp_path, e_temp_rm)

            return FileProcessResult(
                filepath=filepath,
                had_marker_or_change=had_marker,
                temp_file_path=temp_path if content_changed else None,
                detected_markers=detected,
                processed_markers=processed,
            )

        except FileNotFoundError:
            self.log.error("File not found: %s", filepath)
            return FileProcessResult(filepath, False, None, "File not found")
        except PermissionError:
            self.log.error("Permission denied for file: %s", filepath)
            return FileProcessResult(filepath, False, None, "Permission denied")
        except Exception as e_file_proc:
            self.log.error("Unexpected error processing %s: %s", filepath, e_file_proc)
            return FileProcessResult(filepath, False, None, f"Unexpected error: {e_file_proc}")

    # ------------------------------------------------------------------
    def _log_file_report(self, filepath: str, line_reports):
        if self.multiple_files:
            self.log.info("\n%s %s", self.log.blue("File:"), filepath)
        for ln, (orig, mod, reps) in sorted(line_reports.items()):
            self.log.info("  %s: Original: %s", self.log.cyan(f"L{ln}"), orig.rstrip())
            if mod != orig:
                self.log.info("  %s: %s %s", self.log.cyan(f"L{ln}"), self.log.cyan("Modified:"), mod.rstrip())
            for rep in reps:
                action_col = (
                    self.log.red(rep.action)
                    if rep.action in ("Removed", "Processed (BOM)")
                    else self.log.magenta(rep.action)
                    if rep.action == "Replaced"
                    else self.log.yellow(rep.action)
                )
                type_col = (
                    self.log.red(rep.marker_type)
                    if rep.marker_type in ("Hidden", "IdeographicVS")
                    else self.log.yellow(rep.marker_type)
                )
                details = f"'{repr(rep.original_char)}' ({rep.description})"
                if rep.replacement:
                    details += f" -> '{repr(rep.replacement)}'"
                self.log.info(
                    "    %s (%s): %s at %s",
                    action_col,
                    type_col,
                    details,
                    self.log.cyan(f"column {rep.char_idx + 1}"),
                )

    # --- File Discovery Functions ---
    def find_files_to_process(
        self,
        file_path: Optional[str] = None,
        dir_path: Optional[str] = None,
        *,
        recursive: bool = False,
        ignored_dir_names: Optional[Set[str]] = None,
        file_patterns: Optional[List[str]] = None,
    ) -> List[str]:
        """Return list of candidate text files honoring globs / recursion."""
        files: List[str] = []
        ignored_dir_names = ignored_dir_names or set()

        # Compile file pattern regex if specified
        pattern_re: Optional[re.Pattern[str]] = None
        if file_patterns:
            regex_parts = [p.replace(".", "\\.").replace("*", ".*").replace("?", ".") for p in file_patterns]
            pattern_re = re.compile(f"^({'|'.join(regex_parts)})$")
            self.log.debug("Using file pattern regex: %s", pattern_re.pattern)

        # Single file mode -------------------------------------------
        if file_path:
            if not os.path.isfile(file_path):
                self.log.error("File '%s' not found.", file_path)
                return []
            if self._is_likely_text_file(file_path):
                files.append(file_path)
                self.log.debug("Added file to process: %s", file_path)
            else:
                if self.multiple_files:
                    self.log.info("Skipping '%s' as it does not appear to be text.", file_path)
            return files

        # Directory mode ---------------------------------------------
        if dir_path:
            if not os.path.isdir(dir_path):
                self.log.error("Directory '%s' not found.", dir_path)
                return []
            self.log.debug("Processing directory: %s (recursive=%s)", dir_path, recursive)
            walker = os.walk(dir_path) if recursive else [(dir_path, [], os.listdir(dir_path))]
            for root, dirs, names in walker:
                # prune ignored dirs when walking recursively
                if recursive:
                    dirs[:] = [d for d in dirs if d not in ignored_dir_names]
                for name in names:
                    if pattern_re and not pattern_re.match(name):
                        continue
                    path = os.path.join(root, name)
                    if os.path.isfile(path) and self._is_likely_text_file(path):
                        files.append(path)
            return files

        # neither file nor dir given
        self.log.warning("No input path provided to find_files_to_process()")
        return []

    # ------------------------------------------------------------------
    def scan(self, files: List[str]) -> ScanStats:
        """Process many files and return accumulated statistics.

        *Does not* automatically commit / overwrite cleaned files - caller can
        walk over results if self.clean_file is True and decide what to do.
        """
        stats = ScanStats(start_time=time.time())
        if len(files) > 1:
            self.multiple_files = True
            self.log.info("Starting scan of %d file(s)...", len(files))
        self._results: Dict[str, FileProcessResult] = {}

        for path in files:
            res = self._process_file(path)
            self._results[path] = res
            stats.update_from_result(res)

        stats.end_time = time.time()
        return stats

    # ------------------------------------------------------------------
    def cleaned_temp_paths(self) -> Dict[str, str]:
        """Return mapping *original -> temp* for files actually modified."""
        return {
            orig: res.temp_file_path
            for orig, res in self._results.items()
            if res.temp_file_path is not None
        }

    # ------------------------------------------------------------------
    def commit_changes(self) -> Tuple[int, int]:
        """Atomically replace originals with cleaned temps. Returns (ok, errors)."""
        ok = err = 0
        for orig, tmp in list(self.cleaned_temp_paths().items()):
            try:
                stat = os.stat(orig)
                os.replace(tmp, orig)
                os.chmod(orig, stat.st_mode)
                ok += 1
            except Exception as e:  # pragma: no cover
                self.log.error("Error committing %s -> %s: %s", tmp, orig, e)
                err += 1
        return ok, err

    # --- Report Generation Functions ---
    def display_summary_report(self, stats: ScanStats):
        """
        Display a summary report of the scan results.
        """
        if self.report_mode == "quiet":
            return
        sep = "=" * 60
        self.log.info("\n%s", sep)
        self.log.info("%s", self.log.blue("SCAN SUMMARY"))
        self.log.info("%s", sep)
        self.log.info("Files processed: %d", stats.files_processed)
        self.log.info("Files with markers: %d", stats.files_with_markers)
        self.log.info("Total markers detected: %d", stats.total_markers_detected)
        if stats.total_markers_processed:
            self.log.info("Total markers processed: %d", stats.total_markers_processed)
        self.log.info("Elapsed time: %.2f s", stats.elapsed_time)
        self.log.info("%s", sep)
        status = (
            self.log.yellow("MARKERS FOUND")
            if stats.files_with_markers
            else self.log.green("NO MARKERS FOUND")
        )
        self.log.info("\nStatus: %s", status)

    # ------------------------------------------------------------------
    #  Build detector straight from argparse.Namespace
    # ------------------------------------------------------------------
    @classmethod
    def from_args(cls, args, logger: Optional[SimpleLogger] = None):
        return cls(
            clean_file=args.clean,
            check_typographic=args.check_typographic,
            check_ivs=args.check_ivs,
            user_excluded_chars=set(getattr(args, "excluded_chars", [])),
            report_mode=args.report_mode,
            logger=logger,
        )

###############################################################################
#  main() - thin CLI for UnicodeMarkerDetector
###############################################################################

def _parse_excluded_chars(vals: List[str], logger: SimpleLogger) -> Set[str]:
    """Convert a list of CLI strings to a set of Unicode characters."""
    out: Set[str] = set()
    for token in vals:
        try:
            tok = token.strip()
            parsed: Optional[str] = None
            if tok.startswith("U+") and len(tok) > 2:
                tok = tok[2:]
            if (4 <= len(tok) <= 6) and tok.isalnum():
                parsed = chr(int(tok, 16))
            elif len(tok) == 1: # Treat as a literal character
                parsed = tok
        finally:
            if parsed:
                out.add(parsed)
                logger.debug(f"Excluding character: '{repr(parsed)}' (U+{ord(parsed):04X})")
            else:
                logger.error("\n%s for --exclude-char '%s'. Use U+XXXX, plain char, or hex.", logger.red("Error: Invalid format"), token)
                raise SystemExit(1)
    return out

def build_arg_parser() -> argparse.ArgumentParser:
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

    return parser


def main(argv: Optional[List[str]] = None) -> None:  # noqa: C901 (long, but straight line)
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    #  Logger setup
    log_levels = {
        "DEBUG": SimpleLogger.DEBUG,
        "INFO": SimpleLogger.INFO,
        "WARNING": SimpleLogger.WARNING,
        "ERROR": SimpleLogger.ERROR,
    }
    log = SimpleLogger(
        level=log_levels[args.log_level],
        use_colors=sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None,
        log_file=args.log_file,
    )

    log.debug("Unicode Marker Detector v%s starting", VERSION)
    log.debug("Log level set to %s", args.log_level)

    # Process excluded characters
    excluded_chars = _parse_excluded_chars(args.excluded_chars_str, log)

    # -- Detector instance --
    detector = UnicodeMarkerDetector(
        clean_file=args.clean,
        check_typographic=args.check_typographic,
        check_ivs=args.check_ivs,
        user_excluded_chars=excluded_chars,
        report_mode=args.report_mode,
        logger=log,
    )

    # -- Build file list --
    if args.stdin:
        log.debug("Reading from standard input")
        try:
            stdin_data = sys.stdin.read()
            stdin_tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
            stdin_tmp.write(stdin_data)
            stdin_tmp.close()
            files_to_process = [stdin_tmp.name]
            original_stdin_tmp = stdin_tmp.name
            log.debug("Created temporary file from stdin: %s", original_stdin_tmp)
        except Exception as e:
            log.error("Error reading from stdin: %s", e)
            raise SystemExit(1)
    else:
        files_to_process = detector.find_files_to_process(
            file_path=args.file,
            dir_path=args.dir,
            recursive=args.recursive,
            ignored_dir_names=set(args.ignored_dirs),
            file_patterns=args.file_patterns,
        )
        original_stdin_tmp = None

    if not files_to_process:
        log.warning("No text files found or selected for processing.")
        raise SystemExit(1)

    # --- Process files ---
    stats = detector.scan(files_to_process)


    # --- Cleanup for stdin mode ---
    if args.stdin:
        tmp_map = detector.cleaned_temp_paths()
        if args.clean and original_stdin_tmp and original_stdin_tmp in tmp_map:
            log.debug("Processing cleaned stdin content")
            with open(tmp_map[original_stdin_tmp], "r", encoding="utf-8") as f:
                sys.stdout.write(f.read())
            os.remove(tmp_map[original_stdin_tmp])
        # always remove the input tmp
        if original_stdin_tmp and os.path.exists(original_stdin_tmp):
            os.remove(original_stdin_tmp)

    # --- Confirmation and commit phase ---
    changed_paths = detector.cleaned_temp_paths()
    if args.clean and changed_paths:
        log.warning("\nModifications prepared for %d file(s).", len(changed_paths))
        proceed = args.auto_confirm_clean
        if not proceed:
            try:
                proceed = input("Save changes? (yes/no): ").strip().lower() == "yes"
            except (KeyboardInterrupt, EOFError):
                log.error("\nNon-interactive environment detected. Discarding changes.")
                log.info("Use -y or --yes to save changes non-interactively.")
                proceed = False
        if proceed:
            log.info("Saving modified files...")
            ok, err = detector.commit_changes()
            log.info("Finished saving: %d file(s); %d error(s).", ok, err)
        else:
            log.info("Changes discarded by user.")

    # Clean up temporary files
    for temp_path in changed_paths.values():
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                log.debug(f"Removed temporary file: {temp_path}")
            except OSError as e:
                log.error(f"Failed to remove temporary file {temp_path}: {e}")

    # --- Generate final report ---
    detector.display_summary_report(stats)

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