FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY graylog_automation_normalize.py /app/graylog_automation_normalize.py

CMD ["python", "/app/graylog_automation_normalize.py"]

