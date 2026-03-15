# Base Image: Lightweight and secure
FROM python:3.11-slim

# Enforce Working Directory
WORKDIR /app

# Prevent Python from writing .pyc files and force unbuffered stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install OS-level dependencies for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Dependency Management
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Inject v9.6 Architecture
COPY . .

# Expose the API Port
EXPOSE 8000

# Execute the OS Core
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

