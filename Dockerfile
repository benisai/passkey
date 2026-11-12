FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/app/data/vault.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home vault && mkdir /app/data && chown vault:vault /app/data
COPY app.py .
COPY static ./static
USER vault
EXPOSE 3100
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3100/health', timeout=3)"
CMD ["gunicorn", "--bind", "0.0.0.0:3100", "--workers", "1", "--threads", "4", "--timeout", "60", "--umask", "0077", "app:app"]
