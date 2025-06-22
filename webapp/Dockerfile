
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and templates into subdir "app"
COPY app /app/app
# COPY templates /app/templates

ENV PYTHONPATH=/app

# Expose port for Flask
EXPOSE 5000

# Run Flask app via main.py in app package
CMD ["python", "app/main.py"]

