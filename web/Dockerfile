FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

RUN groupadd --system --gid 1000 app && useradd --system --uid 1000 --gid app app

COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY web/app.py .
COPY web/templates .
COPY hidden-characters-detector.py ./unicode_detector.py

RUN chown -R app:app /app

USER app

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]

