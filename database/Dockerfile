# Use the official PostgreSQL image from the Docker Hub
FROM postgres:16

# Set environment variables for the PostgreSQL database
ENV POSTGRES_DB APAnalyzer
ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD kali

# Copy the initialization SQL script to the Docker entrypoint directory
COPY init.sql /docker-entrypoint-initdb.d/