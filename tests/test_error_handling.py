import unittest
import tempfile
import os
import shutil
from pathlib import Path
import stat # For permission changes

# Assuming test_utils.py
from test_utils import (
    run_script, create_temp_file, read_file_content,
    ZERO_WIDTH_SPACE, NORMAL_TEXT
)

class TestErrorHandling(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="um_err_")

    def tearDown(self):
        # Ensure all permissions are restored before shutil.rmtree
        # In a more complex scenario, you'd track and restore specific permissions.
        # For now, making the dir writable should be enough for rmtree.
        os.chmod(self.test_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        for root, dirs, files in os.walk(self.test_dir):
            for d_name in dirs:
                os.chmod(os.path.join(root, d_name), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            for f_name in files:
                try:
                    os.chmod(os.path.join(root, f_name), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                except OSError:
                    pass # Might fail if symlink etc., handle gracefully
        shutil.rmtree(self.test_dir)


    def test_file_not_found(self):
        non_existent_file = Path(self.test_dir) / "ghost.txt"
        result = run_script(["-f", str(non_existent_file)])
        # The script exits with 1 if no files are processed.
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"File '{non_existent_file}' not found", result.stdout) # Script's own error log
        self.assertIn("No text files found or selected for processing.", result.stdout)


    def test_directory_not_found(self):
        non_existent_dir = Path(self.test_dir) / "no_such_dir"
        result = run_script(["-d", str(non_existent_dir)])
        self.assertEqual(result.returncode, 1) # Script exits if no files found
        self.assertIn(f"Directory '{non_existent_dir}' not found", result.stdout)
        self.assertIn("No text files found or selected for processing.", result.stdout)


    def test_processing_binary_file(self):
        # Create a file with a null byte, which is_likely_text_file should reject
        binary_file = create_temp_file(self.test_dir, "binary.dat", content="Hello\x00World")
        result = run_script(["-f", str(binary_file)])
        self.assertEqual(result.returncode, 1) # Exits 1 as no *text* files processed
        self.assertIn(f"Skipping '{binary_file}' as it does not appear to be text.", result.stdout)
        self.assertIn("No text files found or selected for processing.", result.stdout)


    @unittest.skipIf(os.name == 'nt', "File permission tests are tricky on Windows")
    def test_permission_denied_reading_file(self):
        no_read_file = create_temp_file(self.test_dir, "no_read.txt", "cant_read_me")
        original_perms = os.stat(no_read_file).st_mode
        os.chmod(no_read_file, 0o000) # No read/write/execute

        result = run_script(["-f", str(no_read_file)])
        os.chmod(no_read_file, original_perms) # Restore perms for cleanup

        # The script's process_file function logs an error but doesn't stop overall execution
        # If it's the only file and it fails, the script might exit 1 due to no successful processing.
        self.assertEqual(result.returncode, 1) # if FileProcessResult is error, but no --fail
                                               # Or 1 if main loop considers this a critical failure for "files_to_process"
                                               # The current script's main() will exit 1 if files_to_process is empty
                                               # OR if no files are *successfully* processed.
                                               # A file that errors in process_file() would count as processed with error, not reducing "files_to_process" len
                                               # Let's assume it logs the error and continues, potentially exiting 0 if no --fail.
                                               # If it was the *only* file, the "no files found" path might be hit in main.
                                               # Given it's found then fails, FileProcessResult has an error.
                                               # The script does not exit(1) explicitly for a single file permission error, relies on --fail.
        self.assertIn(f"No text files found or selected for processing", result.stdout)

    @unittest.skipIf(os.name == 'nt', "File permission tests are tricky on Windows")
    def test_permission_denied_creating_temp_file_for_clean(self):
        # Create a file in a directory that will become non-writable
        target_dir_for_file = Path(self.test_dir) / "sub"
        target_dir_for_file.mkdir()
        file_to_clean = create_temp_file(target_dir_for_file, "locked_clean.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")

        original_dir_perms = os.stat(target_dir_for_file).st_mode
        os.chmod(target_dir_for_file, 0o500)  # Read and execute, but not write

        result = run_script(["-f", str(file_to_clean), "-c", "-y"])
        os.chmod(target_dir_for_file, original_dir_perms) # Restore

        self.assertEqual(result.returncode, 0) # Script handles error per file
        self.assertIn(f"Could not create temporary file in {target_dir_for_file}", result.stdout)
        self.assertEqual(read_file_content(file_to_clean), f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}") # Unchanged

    # @unittest.skipIf(os.name == 'nt', "File permission tests are tricky on Windows")
    # def test_permission_denied_saving_cleaned_file(self):
    #     # Temp file can be created in self.test_dir, but original is non-writable
    #     locked_file = create_temp_file(self.test_dir, "locked_original.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")
    #     original_file_perms = os.stat(locked_file).st_mode
    #     os.chmod(locked_file, 0o400) # Read-only

    #     result = run_script(["-f", str(locked_file), "-c", "-y"])
    #     os.chmod(locked_file, original_file_perms) # Restore

    #     self.assertEqual(result.returncode, 0)
    #     self.assertIn(f"Error saving changes for {str(locked_file)}", result.stdout)
    #     self.assertIn("Permission denied", result.stdout) # OS error message part
    #     self.assertEqual(read_file_content(locked_file), f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}") # Unchanged

    @unittest.skipIf(os.name == 'nt', "File permission tests are tricky on Windows")
    def test_permission_preservation_with_os_replace(self):
        # Create test file with content that needs cleaning
        locked_file = create_temp_file(self.test_dir, "permission_test.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")

        # Set specific permissions that should be preserved
        os.chmod(locked_file, 0o644)  # Standard file permissions
        original_stat = os.stat(locked_file)
        original_perms = original_stat.st_mode

        # Run the scripttest_permission_denied_reading_file
        result = run_script(["-f", str(locked_file), "-c", "-y"])

        # Check results
        self.assertEqual(result.returncode, 0)

        # Verify content was cleaned
        current_content = read_file_content(locked_file)
        self.assertEqual(current_content, NORMAL_TEXT)  # ZERO_WIDTH_SPACE should be removed

        # Verify permissions are preserved after os.replace()
        current_stat = os.stat(locked_file)
        self.assertEqual(current_stat.st_mode, original_perms,
                        "File permissions were not preserved after os.replace()")

    @unittest.skipIf(os.name == 'nt', "File permission tests are tricky on Windows")
    def test_directory_permission_denied(self):
        # Create a subdirectory with limited permissions
        restricted_dir = os.path.join(self.test_dir, "restricted")
        os.makedirs(restricted_dir)
        # Create file in restricted directory
        test_file = create_temp_file(restricted_dir, "test.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")
        original_file_perms = os.stat(test_file).st_mode
        # Make directory non-writable (this prevents os.replace())
        os.chmod(restricted_dir, 0o555)  # Read+execute only
        try:
            # Try to run script - should fail during os.replace()
            result = run_script(["-f", str(test_file), "-c", "-y"])
            # On most systems, this should fail
            self.assertNotEqual(result.returncode, 1)
            self.assertIn("Permission denied", result.stdout)
            # File should be unchanged
            self.assertEqual(read_file_content(test_file), f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")
        finally:
            # Restore permissions for cleanup
            os.chmod(restricted_dir, 0o755)
            os.chmod(test_file, original_file_perms)

    @unittest.skipIf(os.name == 'nt', "File permission tests are tricky on Windows")
    def test_read_only_file_in_writable_directory(self):
        # This tests the scenario where the script can use os.replace() successfully
        # but needs to preserve the original file's permissions
        test_file = create_temp_file(self.test_dir, "readonly_file.txt", f"{NORMAL_TEXT}{ZERO_WIDTH_SPACE}")
        # Make file read-only but directory is writable
        os.chmod(test_file, 0o444)  # Read-only for all
        original_perms = os.stat(test_file).st_mode
        # Script should succeed because directory is writable (os.replace works)
        result = run_script(["-f", str(test_file), "-c", "-y"])
        # Check that script succeeded
        self.assertEqual(result.returncode, 0)
        # Check content was cleaned
        self.assertEqual(read_file_content(test_file), NORMAL_TEXT)
        # Check permissions were preserved
        current_perms = os.stat(test_file).st_mode
        self.assertEqual(current_perms, original_perms,
                        "Script should preserve original file permissions after os.replace()")

if __name__ == "__main__":
    unittest.main()