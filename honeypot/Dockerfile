FROM python:3.11-slim

WORKDIR /app

COPY honeypot.py http_honeypot.py ssh_honeypot.py logger.py requirements.txt ./
COPY http_templates ./http_templates

# Create logs directory
RUN mkdir -p /app/logs

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80 22

CMD ["python", "-u", "honeypot.py"]
