# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command (optional if overridden by docker-compose)
CMD ["celery", "-A", "main.celery_app", "worker", "--loglevel=info"]