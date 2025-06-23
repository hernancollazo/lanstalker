
FROM python:3.11-slim

# Install nmap
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /xmls

# Set working directory
WORKDIR /app

# Copy Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner source code into subdir "app"
COPY app /app/app

ENV PYTHONPATH=/app

# Run scanner module
CMD ["python", "app/scanner.py"]
