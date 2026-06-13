FROM python:3.14-bookworm

# Install some system packages
RUN apt-get update && apt-get install -y \
    bluetooth \
    bluez \
    python3-bluez \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create directory
WORKDIR /app
# Copy and install python requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
# Copy the python files
COPY ./main .

# Start the python script
ENTRYPOINT ["python", "-u", "/app/mqtt_client.py"]
