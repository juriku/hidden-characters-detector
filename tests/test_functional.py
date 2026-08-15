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
    BOM, NORMAL_TEXT, THIN_SPACE, IDEOGRAPHIC_SPACE, PATHSPEC_AVAILABLE
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
        self.assertEqual(result.stdout, "")
        self.assertIn("Zero Width Space", result.stderr)
        self.assertIn("Detected", result.stderr)
        self.assertIn("MARKERS FOUND", result.stderr)

    def test_stdin_cleaning(self):
        stdin_content = f"Input {LEFT_DOUBLE_QUOTE}quotes{RIGHT_DOUBLE_QUOTE}"
        expected_cleaned_output = f"Input {STRAIGHT_DOUBLE_QUOTE}quotes{STRAIGHT_DOUBLE_QUOTE}"
        result = run_script(["--stdin", "-c", "-y", "--check-typographic"], stdin_data=stdin_content)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, expected_cleaned_output)
        self.assertIn("Replaced", result.stderr)
        self.assertIn("Left Double Quotation Mark", result.stderr)

    def test_stdin_cleaning_reports_no_commit_error(self):
        stdin_content = f"Input {LEFT_DOUBLE_QUOTE}quotes{RIGHT_DOUBLE_QUOTE}"
        result = run_script(["--stdin", "-c", "-y"], stdin_data=stdin_content)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Error committing", result.stderr)
        self.assertNotIn("error(s)", result.stderr)


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
        self.assertIn("hidden-characters-detector.py 1.2.0", result.stdout) # Adjust to actual script name in output


@unittest.skipUnless(PATHSPEC_AVAILABLE, "pathspec is not installed; .gitignore support is disabled")
class TestGitignore(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="um_gitignore_")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_gitignore_honored_by_default(self):
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        sub = root / "sub"
        sub.mkdir()
        create_temp_file(root, ".gitignore", "secret.txt\nsub/\n")
        create_temp_file(root, "secret.txt", f"S{ZERO_WIDTH_SPACE}")
        create_temp_file(root, "keep.txt", f"K{ZERO_WIDTH_SPACE}")
        create_temp_file(sub, "hidden.txt", f"H{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "-r"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("keep.txt", result.stdout)
        self.assertNotIn("secret.txt", result.stdout)
        self.assertNotIn("hidden.txt", result.stdout)

    def test_no_gitignore_flag_disables_filtering(self):
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        sub = root / "sub"
        sub.mkdir()
        create_temp_file(root, ".gitignore", "secret.txt\nsub/\n")
        create_temp_file(root, "secret.txt", f"S{ZERO_WIDTH_SPACE}")
        create_temp_file(sub, "hidden.txt", f"H{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "-r", "--no-gitignore"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("secret.txt", result.stdout)
        self.assertIn("hidden.txt", result.stdout)

    def test_nested_gitignore_applies_only_within_subtree(self):
        # A nested .gitignore that ignores "test" inside ./test2 must NOT
        # affect ./test at the root — only ./test2/test should be skipped.
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        test2 = root / "test2"
        test2.mkdir()
        create_temp_file(test2, ".gitignore", "test\n")
        create_temp_file(root, "test", f"RootTest{ZERO_WIDTH_SPACE}")
        create_temp_file(test2, "test", f"SubTest{ZERO_WIDTH_SPACE}")
        create_temp_file(test2, "keep.txt", f"SubKeep{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "-r"])
        self.assertEqual(result.returncode, 0)
        # Root file named "test" is kept (nested .gitignore has no reach here).
        self.assertIn(f"File: {root}/test\n", result.stdout)
        # Sibling in the nested dir is scanned.
        self.assertIn(f"File: {test2}/keep.txt", result.stdout)
        # The nested "test" file is ignored.
        self.assertNotIn(f"File: {test2}/test\n", result.stdout)

    def test_deeply_nested_gitignore_stacks(self):
        # Patterns from each level must stack: root ignores *.tmp,
        # a/.gitignore adds "drop.txt", a/b/.gitignore adds "local/".
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        a = root / "a"
        a.mkdir()
        b = a / "b"
        b.mkdir()
        local_dir = b / "local"
        local_dir.mkdir()

        create_temp_file(root, ".gitignore", "*.tmp\n")
        create_temp_file(a, ".gitignore", "drop.txt\n")
        create_temp_file(b, ".gitignore", "local/\n")

        create_temp_file(root, "root_ok.txt", f"RO{ZERO_WIDTH_SPACE}")
        create_temp_file(a, "drop.txt", f"D{ZERO_WIDTH_SPACE}")
        create_temp_file(a, "keep.txt", f"KA{ZERO_WIDTH_SPACE}")
        create_temp_file(b, "skip.tmp", f"S{ZERO_WIDTH_SPACE}")
        create_temp_file(b, "keep.txt", f"KB{ZERO_WIDTH_SPACE}")
        create_temp_file(local_dir, "hidden.txt", f"H{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "-r"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"{root}/root_ok.txt", result.stdout)
        self.assertIn(f"{a}/keep.txt", result.stdout)
        self.assertIn(f"{b}/keep.txt", result.stdout)
        self.assertNotIn("drop.txt", result.stdout)          # a/drop.txt ignored
        self.assertNotIn("skip.tmp", result.stdout)          # *.tmp from root
        self.assertNotIn("hidden.txt", result.stdout)        # local/ from b

    def test_gitignore_negation_pattern(self):
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        create_temp_file(root, ".gitignore", "*.log\n!keep.log\n")
        create_temp_file(root, "drop.log", f"D{ZERO_WIDTH_SPACE}")
        create_temp_file(root, "keep.log", f"K{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "-r"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("keep.log", result.stdout)
        self.assertNotIn("drop.log", result.stdout)

    def test_gitignore_non_recursive_top_level_only(self):
        # Explicit --no-recursive: sub/ must not be entered at all,
        # and top-level .gitignore still applies.
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        sub = root / "sub"
        sub.mkdir()
        create_temp_file(root, ".gitignore", "secret.txt\n")
        create_temp_file(root, "secret.txt", f"S{ZERO_WIDTH_SPACE}")
        create_temp_file(root, "keep.txt", f"K{ZERO_WIDTH_SPACE}")
        create_temp_file(sub, "deep.txt", f"D{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "--no-recursive"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("keep.txt", result.stdout)
        self.assertNotIn("secret.txt", result.stdout)
        self.assertNotIn("deep.txt", result.stdout)


class TestDefaultFlags(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="um_defaults_")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_recursive_is_default(self):
        # No -r flag: subdir files must still be scanned.
        # Need >1 file so per-file "File: ..." headers appear in output.
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        sub = root / "nested"
        sub.mkdir()
        create_temp_file(root, "top.txt", f"Top{ZERO_WIDTH_SPACE}")
        create_temp_file(sub, "deep.txt", f"Deep{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root)])
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"{sub}/deep.txt", result.stdout)
        self.assertIn("Files processed: 2", result.stdout)

    def test_no_recursive_opt_out(self):
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        sub = root / "nested"
        sub.mkdir()
        create_temp_file(root, "top.txt", f"Top{ZERO_WIDTH_SPACE}")
        create_temp_file(sub, "deep.txt", f"Deep{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root), "--no-recursive"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 1", result.stdout)
        self.assertNotIn("deep.txt", result.stdout)

    def test_check_typographic_is_default(self):
        # Em dash detected without passing --check-typographic.
        test_file = create_temp_file(self.test_dir, "typo.txt", f"dash{EM_DASH}here")
        result = run_script(["-f", str(test_file)])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Em Dash (U+2014)", result.stdout)

    def test_no_check_typographic_opt_out(self):
        test_file = create_temp_file(self.test_dir, "typo.txt", f"dash{EM_DASH}here")
        result = run_script(["-f", str(test_file), "--no-check-typographic"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("NO MARKERS FOUND", result.stdout)

    def test_check_ivs_is_default(self):
        test_file = create_temp_file(self.test_dir, "ivs.txt", f"IVS{IDEOGRAPHIC_VS}char")
        result = run_script(["-f", str(test_file)])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Ideographic Variation Selector", result.stdout)

    def test_no_check_ivs_opt_out(self):
        test_file = create_temp_file(self.test_dir, "ivs.txt", f"IVS{IDEOGRAPHIC_VS}char")
        result = run_script(["-f", str(test_file), "--no-check-ivs"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("NO MARKERS FOUND", result.stdout)

    def test_git_dir_ignored_by_default(self):
        root = Path(self.test_dir) / "proj"
        root.mkdir()
        git_dir = root / ".git"
        git_dir.mkdir()
        create_temp_file(git_dir, "config", f"inside-git{ZERO_WIDTH_SPACE}")
        create_temp_file(root, "code.txt", f"Code{ZERO_WIDTH_SPACE}")

        result = run_script(["-d", str(root)])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 1", result.stdout)
        self.assertNotIn(".git/config", result.stdout)

class TestDefaultIgnoredDirs(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="um_ignoredirs_")
        self.root = Path(self.test_dir) / "proj"
        self.root.mkdir()
        create_temp_file(self.root, "src.txt", f"Src{ZERO_WIDTH_SPACE}")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _make_dir_with_marker(self, name):
        target = self.root / name
        target.mkdir()
        create_temp_file(target, "dep.txt", f"Dep{ZERO_WIDTH_SPACE}")
        return target

    def test_node_modules_ignored_by_default(self):
        self._make_dir_with_marker("node_modules")
        result = run_script(["-d", str(self.root), "--no-gitignore"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 1", result.stdout)
        self.assertNotIn("node_modules", result.stdout)

    def test_cache_dirs_ignored_by_default(self):
        for name in ("__pycache__", ".venv", ".terraform", ".pytest_cache"):
            self._make_dir_with_marker(name)
        result = run_script(["-d", str(self.root), "--no-gitignore"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 1", result.stdout)

    def test_no_default_ignores_descends_into_them(self):
        self._make_dir_with_marker("node_modules")
        result = run_script(["-d", str(self.root), "--no-gitignore", "--no-default-ignores"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 2", result.stdout)
        self.assertIn("node_modules", result.stdout)

    def test_git_still_ignored_with_no_default_ignores(self):
        self._make_dir_with_marker(".git")
        result = run_script(["-d", str(self.root), "--no-gitignore", "--no-default-ignores"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 1", result.stdout)

    def test_ignore_dir_adds_to_defaults_rather_than_replacing(self):
        self._make_dir_with_marker("node_modules")
        self._make_dir_with_marker("custom_dir")
        result = run_script(["-d", str(self.root), "--no-gitignore", "--ignore-dir", "custom_dir"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 1", result.stdout)

    def test_ambiguous_build_dirs_are_still_scanned(self):
        for name in ("dist", "build", "target", "vendor"):
            self._make_dir_with_marker(name)
        result = run_script(["-d", str(self.root), "--no-gitignore"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Files processed: 5", result.stdout)


class TestCleaningFidelity(unittest.TestCase):
    """Cleaning must preserve word boundaries and the file's original encoding."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="um_fidelity_")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_nbsp_becomes_space_not_deleted(self):
        test_file = create_temp_file(self.test_dir, "nbsp.txt", f"two{NON_BREAKING_SPACE}words")
        result = run_script(["-f", str(test_file), "-c", "-y"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(read_file_content(test_file), "two words")

    def test_exotic_spaces_become_regular_spaces(self):
        content = f"a{THIN_SPACE}b{IDEOGRAPHIC_SPACE}c"
        test_file = create_temp_file(self.test_dir, "spaces.txt", content)
        result = run_script(["-f", str(test_file), "-c", "-y"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(read_file_content(test_file), "a b c")

    def test_zero_width_characters_are_still_removed(self):
        test_file = create_temp_file(self.test_dir, "zwsp.txt", f"one{ZERO_WIDTH_SPACE}word")
        result = run_script(["-f", str(test_file), "-c", "-y"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(read_file_content(test_file), "oneword")

    def test_latin1_file_is_not_transcoded(self):
        # Padded with ASCII: the binary-file heuristic needs >75% printable bytes.
        test_file = Path(self.test_dir) / "latin.txt"
        test_file.write_bytes(f"café{NON_BREAKING_SPACE}bar and some ascii padding".encode("latin-1"))

        result = run_script(["-f", str(test_file), "-c", "-y"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(test_file.read_bytes(), "café bar and some ascii padding".encode("latin-1"))

    def test_undecodable_file_is_skipped_not_corrupted(self):
        # Encoding detection only reads the file's head, so the bad byte must sit
        # past the read buffer to survive detection.
        test_file = Path(self.test_dir) / "broken.txt"
        original = b"a" * 16384 + b"\xff" + f"{ZERO_WIDTH_SPACE}".encode("utf-8")
        test_file.write_bytes(original)

        result = run_script(["-f", str(test_file), "-c", "-y"])

        self.assertIn("skipped to avoid corrupting it", result.stdout)
        self.assertEqual(test_file.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()