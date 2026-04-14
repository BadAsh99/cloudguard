FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

# Railway injects $PORT — fall back to 8080 for local docker runs
CMD gunicorn --bind "0.0.0.0:${PORT:-8080}" --workers 2 --timeout 120 app:app
