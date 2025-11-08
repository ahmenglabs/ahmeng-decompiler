# Use Ubuntu as base image
FROM ubuntu:20.04

# Set non-interactive frontend to avoid timezone prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install Java (required for Ghidra) - JDK 21
RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    wget \
    unzip \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip \
    && unzip ghidra_11.4.2_PUBLIC_20250826.zip \
    && rm ghidra_11.4.2_PUBLIC_20250826.zip

# Set environment variables
ENV GHIDRA_HOME=/ghidra_11.4.2_PUBLIC
ENV PATH=$PATH:$GHIDRA_HOME/support

# Copy backend code
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip3 install -r requirements.txt

COPY backend/ .

# Copy environment file
COPY .env ./backend/

# Copy backend code

# Copy Decompile.java to Ghidra scripts directory
RUN mkdir -p $GHIDRA_HOME/Ghidra/Features/Decompiler/ghidra_scripts
COPY backend/Decompile.java $GHIDRA_HOME/Ghidra/Features/Decompiler/ghidra_scripts/

# Copy frontend code and build
WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Copy frontend code and build
WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Expose ports
EXPOSE 5000 5173

# Create startup script
RUN echo '#!/bin/bash\ncd /app/backend && python3 app.py &\ncd /app && npm run preview -- --host 0.0.0.0 --port 5173' > /start.sh \
    && chmod +x /start.sh

CMD ["/start.sh"]