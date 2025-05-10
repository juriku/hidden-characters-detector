import unittest
import tempfile
import shutil
from pathlib import Path

# Assuming test_utils.py
from test_utils import run_script, create_temp_file

class TestInputValidation(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="um_input_val_")
        self.sample_file = create_temp_file(self.test_dir, "sample.txt", "content")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_no_input_source(self):
        result = run_script([])
        self.assertNotEqual(result.returncode, 0) # argparse typically exits with 2
        self.assertIn("error: one of the arguments -f/--file -d/--dir --stdin is required", result.stderr.lower())

    def test_mutually_exclusive_inputs(self):
        result = run_script(["-f", str(self.sample_file), "-d", self.test_dir])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not allowed with argument", result.stderr)

    def test_invalid_exclude_char_format(self):
        # The script itself exits with 1 for this custom validation
        result = run_script(["-f", str(self.sample_file), "--exclude-char", "INVALID_FORMAT"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid format for --exclude-char", result.stdout) # Script logs this as error then exits

    def test_invalid_report_mode(self):
        result = run_script(["-f", str(self.sample_file), "--report-mode", "nonexistent"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice: 'nonexistent'", result.stderr)

    def test_invalid_log_level(self):
        result = run_script(["-f", str(self.sample_file), "--log-level", "VERY_VERBOSE"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice: 'VERY_VERBOSE'", result.stderr)

if __name__ == "__main__":
    unittest.main()