FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# usage: docker run --rm -it webosint example.com -m dns,whois
ENTRYPOINT ["python", "/app/webosint.py"]
