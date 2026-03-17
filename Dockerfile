FROM python:3.11-slim

WORKDIR /app

COPY secret_scanner.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "secret_scanner.py"]