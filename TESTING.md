## To Run the Tests:


Run each test file:
```
python -m unittest test_functional.py
python -m unittest test_input_validation.py
python -m unittest test_error_handling.py
````

Or, if you have pytest installed (recommended):

pytest (Pytest will automatically discover and run tests in files named test_*.py or *_test.py)
This comprehensive set of external tests should give you good coverage of your script's functionality, input handling, and error resilience. Remember that file permission tests can be flaky or behave differently across operating systems.

```
pytest ./tests
```