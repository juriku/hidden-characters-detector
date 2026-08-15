## To Run the Tests

Make sure the dependencies are installed:

```
pip install -r requirements.txt
```

`pathspec` is optional. Without it the `.gitignore` tests skip rather than fail,
which is what the `test-without-optional-deps` CI job verifies.

The tests import `test_utils` as a sibling module, so run them from inside the `tests/` directory:

```
cd tests
python -m unittest discover
```

Or run an individual file or class:

```
cd tests
python -m unittest test_functional
python -m unittest test_functional.TestGitignore
python -m unittest test_functional.TestDefaultFlags
python -m unittest test_input_validation
python -m unittest test_error_handling
```

Or, if you have pytest installed (it will auto-discover `test_*.py` files):

```
pytest ./tests
```

### Test Suites

- **`test_functional.py`** - end-to-end scan/clean behavior, stdin mode, recursive walks, gitignore handling (nested, negation), default-on flags (`-r`, `--check-typographic`, `--check-ivs`), and cleaning fidelity (space normalization, encoding preservation).
- **`test_input_validation.py`** - CLI argument validation, including that running with no input defaults to scanning the current working directory.
- **`test_error_handling.py`** - missing files, permission errors, malformed inputs.

File-permission tests can behave differently across operating systems and are occasionally flaky on CI.