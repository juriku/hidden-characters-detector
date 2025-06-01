import os
import tempfile
import io
import re
import secrets
import logging
import shutil
from flask import Flask, render_template, request, abort, send_file, g, jsonify
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge, HTTPException
import datetime
from typing import Optional # <<< Added Import

from unicode_detector import UnicodeMarkerDetector, SimpleLogger

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB limit

ALLOWED_EXTENSIONS = {'txt', 'log', 'py', 'js', 'html', 'css', 'json', 'xml', 'csv', 'md', 'rst'}

# --- Production Logging Setup ---
if not app.debug:
    log_handler = logging.FileHandler('error.log')
    log_handler.setLevel(logging.ERROR)
    log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    log_handler.setFormatter(log_formatter)
    app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup in production mode')
else:
    app.logger.setLevel(logging.DEBUG)
    app.logger.info('Application startup in debug mode')


# --- Request Hooks ---
@app.before_request
def before_request():
    g.year = datetime.date.today().year
    g.csp_nonce = secrets.token_hex(16)
    # Create a temporary directory for this specific request/session
    try:
        g.request_temp_dir = tempfile.mkdtemp(prefix='req_unicode_')
        app.logger.debug(f"Created request temp dir: {g.request_temp_dir}")
    except Exception as e:
        app.logger.error(f"Failed to create request temp dir: {e}", exc_info=True)
        g.request_temp_dir = None
        abort(500, description="Could not create temporary directory for request.")

@app.after_request
def apply_security_headers(response):
    # Ensure g has csp_nonce, generate if missing (e.g., during error handling before request finishes)
    nonce = getattr(g, 'csp_nonce', secrets.token_hex(16))

    csp_policy_parts = [
        f"default-src 'self'",
        f"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
        f"font-src 'self' https://fonts.gstatic.com",
        f"script-src 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com",
        f"object-src 'none'",
        f"base-uri 'self'",
        f"form-action 'self'",
        f"frame-ancestors 'none'",
    ]
    # Only add report-uri in non-debug environments if needed
    # if not app.debug:
    #     csp_policy_parts.append("report-uri /csp-report-endpoint") # Example endpoint

    response.headers['Content-Security-Policy'] = "; ".join(csp_policy_parts)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    if request.is_secure: # Only send HSTS over HTTPS
         response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# --- Cleanup Temporary Directory ---
@app.teardown_request
def teardown_request_temp_dir(exception=None):
    temp_dir = getattr(g, 'request_temp_dir', None)
    if temp_dir and os.path.exists(temp_dir):
        try:
            shutil.rmtree(temp_dir)
            app.logger.debug(f"Cleaned up request temp dir: {temp_dir}")
        except Exception as e:
            app.logger.error(f"Error cleaning up request temp dir {temp_dir}: {e}", exc_info=True)
    if exception:
        # Log the exception that might have occurred during the request
        app.logger.error(f"Request teardown triggered by exception: {exception}", exc_info=exception)


# --- WebLogger (for user feedback - remains the same) ---
class WebLogger(SimpleLogger):
    # ... (WebLogger code as before) ...
    def __init__(self, level: int = SimpleLogger.INFO, use_colors: bool = False):
        super().__init__(level, use_colors)
        self.log_capture = io.StringIO()

    def _log(self, level: int, msg: str, *args, color: Optional[str] = None) -> None:
        if level < self.level:
            return
        if args:
            msg = msg % args

        clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        self.log_capture.write(clean_msg + "\n")

    def get_captured_logs(self) -> str:
        return self.log_capture.getvalue()

    def reset_capture(self):
        self.log_capture.truncate(0)
        self.log_capture.seek(0)

    def close(self):
        pass


# --- Helper function for allowed file extensions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Error Handlers ---
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    # Log specific HTTP errors
    app.logger.warning(f'HTTP Exception {e.code} ({e.name}): {request.path} - {e.description}')
    # Return JSON for API-like errors, could render template for user-facing errors
    response = e.get_response()
    if "text/html" in response.content_type:
      response.data = jsonify(
          error=e.name,
          message=e.description,
          code=e.code
      ).data
    response.content_type = "application/json"
    return response

@app.errorhandler(Exception) # Catch non-HTTP exceptions (like 500s)
def handle_generic_exception(e):
    # Log unexpected server errors
    app.logger.error(f'Unhandled Exception: {e}', exc_info=True)
    # Avoid leaking details in production
    error_message = "An internal server error occurred." if not app.debug else str(e)
    return jsonify(error="Internal Server Error", message=error_message), 500

# Specific handler for file size limit (inherits from HTTPException)
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    app.logger.warning(f'File upload rejected: Too large (limit: {app.config["MAX_CONTENT_LENGTH"]} bytes)')
    return jsonify(error="File Too Large", message=f"The file must be less than {app.config['MAX_CONTENT_LENGTH'] // 1024 // 1024}MB."), 413


# --- Main Route (`/`) ---
@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    error_message = None
    log_output = ""

    cleaned_text_for_display = None
    cleaned_content_for_download = None
    download_available = False
    original_input_was_file = False
    cleaning_performed_no_changes = False
    filename_for_download = "cleaned_text.txt"

    web_logger = WebLogger(level=SimpleLogger.INFO)

    if request.method == 'GET':
        form_data = {
            'clean_file': True,
            'check_typographic': True,
            'check_ivs': True,
            'exclude_word_chars': False,
            'excluded_chars': '',
            'report_mode': 'normal',
            'text_input': ''
        }
        original_text_input_value = ''
    else: # POST request
        form_data = {
         'clean_file': bool('clean_file' in request.form),
            'check_typographic': bool('check_typographic' in request.form),
            'check_ivs': bool('check_ivs' in request.form),
            'exclude_word_chars': bool('exclude_word_chars' in request.form),
            'excluded_chars': request.form.get('excluded_chars', ''),
            'report_mode': request.form.get('report_mode', 'normal'),
            'text_input': request.form.get('text_input', '')
        }
        original_text_input_value = form_data['text_input']

        web_logger.reset_capture()

        text_input_from_form = form_data['text_input']
        file_input = request.files.get('file_input')

        input_provided = False
        original_filename_secure = None

        request_temp_dir = getattr(g, 'request_temp_dir', None)
        if not request_temp_dir:
             app.logger.error("Request temp directory not available in index route during POST.")
             return jsonify(error="Configuration Error", message="Temporary processing space unavailable."), 500

        if file_input and file_input.filename:
            original_input_was_file = True
            input_provided = True
            if not allowed_file(file_input.filename):
                error_message = "Invalid file type. Allowed types: " + ", ".join(ALLOWED_EXTENSIONS)
            else:
                 original_filename_secure = secure_filename(file_input.filename)
                 if not original_filename_secure:
                     error_message = "Invalid filename provided."
        elif text_input_from_form:
             original_input_was_file = False
             input_provided = True
        else:
             error_message = "Please provide text input or upload a file."
             input_provided = False

        if input_provided and not error_message:
            excluded_chars_str_list = form_data['excluded_chars'].split(',')
            excluded_chars_set = set()
            if form_data['excluded_chars'] and excluded_chars_str_list[0]:
                try:
                    for char_val in excluded_chars_str_list:
                        char_val = char_val.strip()
                        if not char_val: continue
                        if char_val.startswith("U+") and len(char_val) > 2 and len(char_val) <= 8:
                             try:
                                excluded_chars_set.add(chr(int(char_val[2:], 16)))
                             except ValueError:
                                web_logger.warning(f"Invalid Unicode format for exclusion: {char_val}")
                        elif len(char_val) == 1:
                            excluded_chars_set.add(char_val)
                        else:
                            web_logger.warning(f"Ignoring invalid exclusion: {char_val}. Use single char or U+XXXX.")
                except Exception as e:
                    web_logger.error(f"Error parsing excluded characters: {e}")

            detector = UnicodeMarkerDetector(
                clean_file=form_data['clean_file'], check_typographic=form_data['check_typographic'],
                check_ivs=form_data['check_ivs'], exclude_word_chars=form_data['exclude_word_chars'], user_excluded_chars=excluded_chars_set,
                report_mode=form_data['report_mode'], logger=web_logger
            )

            temp_input_file_path = None
            detector_cleaned_file_path = None # Define here for finally block

            try:
                temp_fd, temp_input_file_path = tempfile.mkstemp(
                    suffix=("_" + original_filename_secure) if original_filename_secure else ".txt",
                    dir=request_temp_dir
                )

                if original_input_was_file:
                    with os.fdopen(temp_fd, 'wb') as tmp:
                        file_input.save(tmp)
                    files_to_process = [temp_input_file_path]
                    filename_for_download = f"cleaned_{original_filename_secure}"
                elif text_input_from_form:
                    with os.fdopen(temp_fd, 'w', encoding='utf-8') as tmp:
                        tmp.write(text_input_from_form)
                    files_to_process = [temp_input_file_path]
                    filename_for_download = "cleaned_pasted_text.txt"

                # --- Run the detector ---
                stats = detector.scan(files_to_process)
                results = stats

                # --- Handle cleaned output ---
                if form_data['clean_file']:
                    if stats.total_markers_processed > 0:
                        cleaned_paths_map = detector.cleaned_temp_paths()
                        # The key is the temp_input_file_path we created
                        if temp_input_file_path in cleaned_paths_map and cleaned_paths_map[temp_input_file_path]:
                            # This is the path to the *output* temp file created by the detector
                            detector_cleaned_file_path = cleaned_paths_map[temp_input_file_path]

                            # Check if the detector's output file exists before reading
                            if os.path.exists(detector_cleaned_file_path):
                                with open(detector_cleaned_file_path, 'r', encoding='utf-8') as cf:
                                    cleaned_content_for_download = cf.read()
                                if cleaned_content_for_download is not None:
                                    download_available = True
                                    if not original_input_was_file:
                                        cleaned_text_for_display = cleaned_content_for_download
                            else:
                                # Should not happen if map contains path, but log if it does
                                cleaning_performed_no_changes = True
                                web_logger.error(f"Detector reported cleaned path {detector_cleaned_file_path} but it does not exist.")

                        else:
                            cleaning_performed_no_changes = True
                            web_logger.warning("Mismatch: total_markers_processed > 0 but no cleaned temp path found in map.")
                    else:
                        web_logger.debug("Cleaning was enabled, but no markers were processed that required changes.")
                log_output = web_logger.get_captured_logs()

            except RequestEntityTooLarge as e:
                 # Let the specific error handler manage the response
                 # Error message is implicitly set via the handler's return
                 error_message = f"File Too Large: The file must be less than {app.config['MAX_CONTENT_LENGTH'] // 1024 // 1024}MB." # Set for display
                 pass
            except Exception as e:
                # Let the generic error handler manage the response
                error_message = "An error occurred during processing." if not app.debug else f"Processing Error: {str(e)}" # Set for display
                app.logger.error(f'Exception during processing: {str(e)}', exc_info=True) # Log detailed error
                log_output = web_logger.get_captured_logs() # Capture logs even on error
            finally:
                # Clean up the *input* temp file we created
                if temp_input_file_path and os.path.exists(temp_input_file_path):
                    try:
                        os.remove(temp_input_file_path)
                    except OSError as e_rm:
                         app.logger.error(f"Error removing input temp file {temp_input_file_path}: {e_rm}")
                # Clean up the *detector's output* temp file if it exists
                if detector_cleaned_file_path and os.path.exists(detector_cleaned_file_path):
                     try:
                         os.remove(detector_cleaned_file_path)
                     except OSError as e_rm_det:
                         app.logger.error(f"Error removing detector's output temp file {detector_cleaned_file_path}: {e_rm_det}")

    # --- Render Template ---
    return render_template(
        'index.html',
        results=results,
        error_message=error_message,
        original_text_input_value=original_text_input_value if request.method == 'POST' else form_data['text_input'],
        log_output=log_output,
        form_data=form_data,
        filename_for_download=filename_for_download,
        cleaned_text_for_display=cleaned_text_for_display,
        cleaned_content_for_download=cleaned_content_for_download,
        download_available=download_available,
        original_input_was_file=original_input_was_file,
        cleaning_performed_no_changes=cleaning_performed_no_changes
    )
    # --- END of previous index route logic ---


# --- Download Route (`/download_cleaned`) ---
@app.route('/download_cleaned', methods=['POST'])
def download_cleaned_text_route():
    cleaned_data = request.form.get('cleaned_data_for_download')
    filename = request.form.get('filename_for_download', 'cleaned_text.txt')

    filename = secure_filename(filename)
    if not filename:
        filename = 'cleaned_output.txt'

    if cleaned_data is None:
        app.logger.warning('Download attempt with no data.')
        return jsonify(error="Bad Request", message="No data provided for download."), 400

    mem_file = io.BytesIO()
    mem_file.write(cleaned_data.encode('utf-8'))
    mem_file.seek(0)

    return send_file(
        mem_file,
        mimetype='text/plain',
        as_attachment=True,
        download_name=filename
    )


is_debug = os.environ.get('FLASK_DEBUG', '0') == '1'

if __name__ == '__main__':
    # Run with Flask's built-in server only for development/debugging
    # Production should use Gunicorn/uWSGI
    if is_debug:
        app.logger.info("Starting Flask development server...")
        # Host 0.0.0.0 makes it accessible on the network (useful for testing in VMs/containers)
        app.run(debug=True, host='0.0.0.0', port=5001)
    else:
         app.logger.warning("Running with __main__ guard, but FLASK_DEBUG is not '1'.")
         app.logger.warning("For production, use a WSGI server like Gunicorn: ")
         app.logger.warning("gunicorn --bind 0.0.0.0:8000 app:app")
         # Optionally, run with limited access if executed directly without debug
         # app.run(debug=False, host='127.0.0.1', port=5000)

