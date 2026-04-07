# Base Image: Lightweight and secure
FROM python:3.11-slim
 
# Enforce Working Directory
WORKDIR /app
 
# Prevent Python from writing .pyc files and force unbuffered stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
 
# Install OS-level dependencies for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
 
# Dependency Management (as root, before user switch)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
# Create non-root user for the Sentinel process
RUN groupadd --system sentinel && \
    useradd --system --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel
 
# Inject application code
COPY . .
 
# Ensure the sentinel user owns the app directory (needed for audit_trail.jsonl writes)
RUN chown -R sentinel:sentinel /app
 
# Drop privileges — no more root
USER sentinel
 
# Expose the API Port
EXPOSE 8000
 
# Execute the OS Core
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
 
