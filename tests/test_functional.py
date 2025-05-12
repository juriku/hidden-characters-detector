import unittest
import tempfile
import os
import shutil
from pathlib import Path

# Assuming test_utils.py is in the same directory or PYTHONPATH
from test_utils import (
    run_script, create_temp_file, read_file_content,
    ZERO_WIDTH_SPACE, NON_BREAKING_SPACE, EM_DASH, LEFT_DOUBLE_QUOTE,
    RIGHT_DOUBLE_QUOTE, HYPHEN_MINUS, STRAIGHT_DOUBLE_QUOTE, IDEOGRAPHIC_VS,
    BOM, NORMAL_TEXT
)

class TestFunctional(unittest.TestCase):

    def setUp(self):
        """Creates a temporary directory before each test."""
        self.test_dir = tempfile.mkdtemp(prefix="um_test_")

    def tearDown(self):
        """Removes the temporary directory after each test."""
        shutil.rmtree(self.test_dir)

    def test_detect_hidden_marker_single_file(self):
        file_content = f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}"
        test_file = create_temp_file(self.test_dir, "hidden.txt", file_content)

        result = run_script(["-f", str(test_file)])

        self.assertEqual(result.returncode, 0)
        self.assertIn("Zero Width Space (U+200B)", result.stdout)
        self.assertIn("Detected", result.stdout)
        self.assertIn("MARKERS FOUND", result.stdout) # Summary
        self.assertEqual(read_file_content(test_file), file_content) # File unchanged

    def test_detect_typographic_marker_single_file(self):
        file_content = f"Em dash—{EM_DASH}—here."
        test_file = create_temp_file(self.test_dir, "typo.txt", file_content)

        result = run_script(["-f", str(test_file), "--check-typographic"])

        self.assertEqual(result.returncode, 0)
        self.assertIn("Em Dash (U+2014)", result.stdout)
        self.assertIn("Detected", result.stdout)
        self.assertEqual(read_file_content(test_file), file_content)

    def test_detect_ivs_marker_single_file(self):
        file_content = f"IVS{IDEOGRAPHIC_VS}char"
        test_file = create_temp_file(self.test_dir, "ivs.txt", file_content)

        result = run_script(["-f", str(test_file), "--check-ivs"])

        self.assertEqual(result.returncode, 0)
        self.assertIn("Ideographic Variation Selector", result.stdout)
        self.assertIn("Detected", result.stdout)

    def test_no_markers_found_single_file(self):
        test_file = create_temp_file(self.test_dir, "clean.txt", NORMAL_TEXT)
        result = run_script(["-f", str(test_file), "--check-typographic", "--check-ivs"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("NO MARKERS FOUND", result.stdout)

    def test_clean_hidden_marker_auto_confirm(self):
        original_content = f"A{ZERO_WIDTH_SPACE}B"
        cleaned_content = "AB"
        test_file = create_temp_file(self.test_dir, "hidden_clean.txt", original_content)

        result = run_script(["-f", str(test_file), "-c", "-y"])

        self.assertEqual(result.returncode, 0)
        self.assertIn("Zero Width Space (U+200B)", result.stdout)
        self.assertIn("Removed", result.stdout)
        self.assertIn("Saving modified files...", result.stdout)
        self.assertEqual(read_file_content(test_file), cleaned_content)

    def test_clean_typographic_marker_auto_confirm(self):
        original_content = f"Quote: {LEFT_DOUBLE_QUOTE}text{RIGHT_DOUBLE_QUOTE} — Dash: {EM_DASH}"
        cleaned_content = f"Quote: {STRAIGHT_DOUBLE_QUOTE}text{STRAIGHT_DOUBLE_QUOTE} - Dash: {HYPHEN_MINUS}"
        test_file = create_temp_file(self.test_dir, "typo_clean.txt", original_content)

        result = run_script(["-f", str(test_file), "-c", "-y", "--check-typographic"])

        self.assertEqual(result.returncode, 0)
        self.assertIn("Replaced", result.stdout)
        self.assertEqual(read_file_content(test_file), cleaned_content)

    def test_clean_ivs_marker_auto_confirm(self):
        original_content = f"Text{IDEOGRAPHIC_VS}WithIVS"
        cleaned_content = "TextWithIVS"
        test_file = create_temp_file(self.test_dir, "ivs_clean.txt", original_content)

        result = run_script(["-f", str(test_file), "-c", "-y", "--check-ivs"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Removed", result.stdout)
        self.assertEqual(read_file_content(test_file), cleaned_content)

    def test_clean_bom_auto_confirm(self):
        original_content = f"{BOM}{NORMAL_TEXT}"
        cleaned_content = NORMAL_TEXT
        test_file = create_temp_file(self.test_dir, "bom_clean.txt", original_content)

        result = run_script(["-f", str(test_file), "-c", "-y"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Processed (BOM)", result.stdout) # Or "Removed" based on script logic
        self.assertEqual(read_file_content(test_file), cleaned_content)

    def test_recursive_directory_scan(self):
        dir_to_scan = Path(self.test_dir) / "scan_root"
        dir_to_scan.mkdir()
        subdir = dir_to_scan / "subdir"
        subdir.mkdir()

        create_temp_file(dir_to_scan, "file1.txt", f"File1{ZERO_WIDTH_SPACE}")
        create_temp_file(subdir, "file2.txt", f"File2{NON_BREAKING_SPACE}")
        create_temp_file(dir_to_scan, "clean_file.txt", NORMAL_TEXT)

        result = run_script(["-d", str(dir_to_scan), "-r"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"File: {dir_to_scan}/file1.txt", result.stdout)
        self.assertIn("Zero Width Space", result.stdout)
        self.assertIn(f"File: {subdir}/file2.txt", result.stdout) # Path separator
        self.assertIn("Non-Breaking Space", result.stdout)
        self.assertNotIn("clean_file.txt", result.stdout) # Unless verbose/different report mode for clean files
        self.assertIn("MARKERS FOUND", result.stdout)

    def test_ignore_directory(self):
        dir_to_scan = Path(self.test_dir) / "scan_root_ignore"
        dir_to_scan.mkdir()
        ignored_subdir = dir_to_scan / ".git"
        ignored_subdir.mkdir()
        another_ignored_subdir = dir_to_scan / "node_modules"
        another_ignored_subdir.mkdir()
        scanned_subdir = dir_to_scan / "src"
        scanned_subdir.mkdir()

        create_temp_file(dir_to_scan, "root.txt", f"Root{ZERO_WIDTH_SPACE}")
        create_temp_file(ignored_subdir, "ignored1.txt", f"IgnoredA{ZERO_WIDTH_SPACE}")
        create_temp_file(another_ignored_subdir, "ignored2.txt", f"IgnoredB{ZERO_WIDTH_SPACE}")
        create_temp_file(scanned_subdir, "source.txt", f"Source{ZERO_WIDTH_SPACE}")

        result = run_script([
            "-d", str(dir_to_scan), "-r",
            "--ignore-dir", ".git",
            "--ignore-dir", "node_modules"
        ])
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"File: {dir_to_scan}/root.txt", result.stdout)
        self.assertIn(f"File: {scanned_subdir}/source.txt", result.stdout)
        self.assertNotIn("ignored1.txt", result.stdout)
        self.assertNotIn("ignored2.txt", result.stdout)

    def test_file_pattern_matching(self):
        dir_to_scan = Path(self.test_dir) / "pattern_scan"
        dir_to_scan.mkdir()
        create_temp_file(dir_to_scan, "script.py", f"Py{ZERO_WIDTH_SPACE}")
        create_temp_file(dir_to_scan, "notes.txt", f"Txt{ZERO_WIDTH_SPACE}")
        create_temp_file(dir_to_scan, "config.py", f"Config{NORMAL_TEXT}")

        result = run_script(["-d", str(dir_to_scan), "--pattern", "*.py"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"File: {dir_to_scan}/script.py", result.stdout)
        self.assertNotIn(f"File: {dir_to_scan}/notes.txt", result.stdout)
        self.assertNotIn(f"File: {dir_to_scan}/config.py", result.stdout) # Clean, so not listed in brief output

    def test_stdin_detection(self):
        stdin_content = f"Input via stdin {ZERO_WIDTH_SPACE} invisible"
        result = run_script(["--stdin"], stdin_data=stdin_content)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Zero Width Space", result.stdout)
        self.assertIn("Detected", result.stdout)
        self.assertIn("MARKERS FOUND", result.stdout)

    def test_stdin_cleaning(self):
        stdin_content = f"Input {LEFT_DOUBLE_QUOTE}quotes{RIGHT_DOUBLE_QUOTE}"
        expected_cleaned_output = f"Input {STRAIGHT_DOUBLE_QUOTE}quotes{STRAIGHT_DOUBLE_QUOTE}"
        result = run_script(["--stdin", "-c", "-y", "--check-typographic"], stdin_data=stdin_content)
        self.assertEqual(result.returncode, 0)
        self.assertIn(expected_cleaned_output, result.stdout)
        self.assertIn("Replaced", result.stdout)
        self.assertIn("Left Double Quotation Mark", result.stdout)


    def test_exclude_char_uxxxx(self):
        file_content = f"A{ZERO_WIDTH_SPACE}B{NON_BREAKING_SPACE}C"
        test_file = create_temp_file(self.test_dir, "exclude_char.txt", file_content)
        result = run_script(["-f", str(test_file), "--exclude-char", "U+200B"])
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Zero Width Space", result.stdout)
        self.assertIn("Non-Breaking Space", result.stdout)

    def test_fail_flag_with_markers(self):
        test_file = create_temp_file(self.test_dir, "fail_me.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")
        result = run_script(["-f", str(test_file), "--fail"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("Zero Width Space", result.stdout)
        self.assertIn("Exiting with status 1", result.stdout) # Check for the specific log message

    def test_report_file_generation(self):
        report_file_path = Path(self.test_dir) / "scan_report.txt"
        test_file = create_temp_file(self.test_dir, "report_src.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")

        result = run_script(["-f", str(test_file), "--report-file", str(report_file_path)])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report_file_path.exists())
        report_content = read_file_content(report_file_path)
        self.assertIn("UNICODE MARKER DETECTOR REPORT", report_content)
        self.assertIn("Files with markers: 1", report_content)

    def test_version_output(self):
        result = run_script(["--version"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("hidden-characters-detector.py 1.0.0", result.stdout) # Adjust to actual script name in output

if __name__ == "__main__":
    unittest.main()