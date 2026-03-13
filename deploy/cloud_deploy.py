"""
deploy/cloud_deploy.py
-----------------------
Cloud Deployment Helper for CyberWatch

Generates ready-to-use deployment configs for:
  - AWS EC2 (Ubuntu)
  - Google Cloud Platform (GCP Compute Engine)
  - Azure Virtual Machine

Run this script to generate all config files:
  python deploy/cloud_deploy.py

Then follow the printed instructions for your chosen platform.
"""

from pathlib import Path

DEPLOY_DIR = Path(__file__).parent


# ── Docker ───────────────────────────────────────────────

DOCKERFILE = """\
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create log directory
RUN mkdir -p logs

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Start dashboard
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
"""

DOCKER_COMPOSE = """\
version: '3.8'

services:
  cyberwatch:
    build: .
    container_name: cyberwatch
    ports:
      - "8501:8501"
    volumes:
      - ./logs:/app/logs          # persist alert logs
      - ./data:/app/data          # mount log files here
      - ./ml:/app/ml              # persist trained model
    environment:
      - STREAMLIT_SERVER_HEADLESS=true
    restart: unless-stopped

  # Optional: run agent pipeline as a separate service
  pipeline:
    build: .
    container_name: cyberwatch-pipeline
    command: python main.py --tail /app/data/access.log
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
      - ./ml:/app/ml
    depends_on:
      - cyberwatch
    restart: unless-stopped
"""

REQUIREMENTS = """\
streamlit>=1.32.0
plotly>=5.18.0
pandas>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
"""

# ── AWS ──────────────────────────────────────────────────

AWS_USERDATA = """\
#!/bin/bash
# AWS EC2 User Data script — runs on first boot (Ubuntu 22.04)
# Installs Docker + deploys CyberWatch automatically

set -e

# Update system
apt-get update -y
apt-get install -y docker.io docker-compose git curl

# Start Docker
systemctl start docker
systemctl enable docker

# Clone your project (replace with your repo URL)
# git clone https://github.com/YOUR_USERNAME/cyberwatch.git /opt/cyberwatch

# Or copy files via S3 (replace bucket name):
# aws s3 cp s3://your-bucket/cyberwatch.zip /opt/cyberwatch.zip
# unzip /opt/cyberwatch.zip -d /opt/cyberwatch

cd /opt/cyberwatch

# Build and start
docker-compose up -d --build

echo "CyberWatch deployed! Access at http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8501"
"""

AWS_SECURITY_GROUP = """\
# AWS CLI commands to create security group
# Run these in your terminal after installing AWS CLI

# 1. Create security group
aws ec2 create-security-group \\
    --group-name cyberwatch-sg \\
    --description "CyberWatch monitoring dashboard"

# 2. Allow Streamlit port (8501) from your IP only
aws ec2 authorize-security-group-ingress \\
    --group-name cyberwatch-sg \\
    --protocol tcp \\
    --port 8501 \\
    --cidr YOUR.IP.ADDRESS/32

# 3. Allow SSH
aws ec2 authorize-security-group-ingress \\
    --group-name cyberwatch-sg \\
    --protocol tcp \\
    --port 22 \\
    --cidr YOUR.IP.ADDRESS/32

# 4. Launch EC2 instance (t3.small is sufficient)
aws ec2 run-instances \\
    --image-id ami-0c7217cdde317cfec \\
    --instance-type t3.small \\
    --security-groups cyberwatch-sg \\
    --user-data file://deploy/aws_userdata.sh \\
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=cyberwatch}]'

# 5. Get public IP
aws ec2 describe-instances \\
    --filters "Name=tag:Name,Values=cyberwatch" \\
    --query "Reservations[*].Instances[*].PublicIpAddress" \\
    --output text
"""

# ── GCP ──────────────────────────────────────────────────

GCP_STARTUP = """\
#!/bin/bash
# GCP Compute Engine startup script (Debian/Ubuntu)

apt-get update -y
apt-get install -y docker.io docker-compose

systemctl start docker
systemctl enable docker

# Pull from GCS bucket (replace with your bucket):
# gsutil cp -r gs://your-bucket/cyberwatch /opt/cyberwatch

cd /opt/cyberwatch
docker-compose up -d --build

echo "Deployed on GCP. Access at http://$(curl -H 'Metadata-Flavor:Google' http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip):8501"
"""

GCP_GCLOUD = """\
# GCP deployment commands (run in terminal with gcloud CLI installed)

# 1. Create firewall rule for Streamlit
gcloud compute firewall-rules create allow-cyberwatch \\
    --allow tcp:8501 \\
    --source-ranges=YOUR.IP.ADDRESS/32 \\
    --description="CyberWatch dashboard access"

# 2. Create VM instance (e2-small is sufficient)
gcloud compute instances create cyberwatch \\
    --machine-type=e2-small \\
    --image-family=ubuntu-2204-lts \\
    --image-project=ubuntu-os-cloud \\
    --metadata-from-file startup-script=deploy/gcp_startup.sh \\
    --tags=cyberwatch \\
    --zone=us-central1-a

# 3. Get external IP
gcloud compute instances describe cyberwatch \\
    --zone=us-central1-a \\
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
"""

# ── Azure ─────────────────────────────────────────────────

AZURE_INIT = """\
#!/bin/bash
# Azure VM cloud-init script

apt-get update -y
apt-get install -y docker.io docker-compose

systemctl start docker
systemctl enable docker

# Copy project from Azure Blob (replace with your container):
# az storage blob download-batch -d /opt/cyberwatch -s cyberwatch-container

cd /opt/cyberwatch
docker-compose up -d --build
"""

AZURE_CLI = """\
# Azure deployment commands

# 1. Create resource group
az group create --name cyberwatch-rg --location eastus

# 2. Create VM (Standard_B1ms is sufficient)
az vm create \\
    --resource-group cyberwatch-rg \\
    --name cyberwatch-vm \\
    --image Ubuntu2204 \\
    --size Standard_B1ms \\
    --admin-username azureuser \\
    --generate-ssh-keys \\
    --custom-data deploy/azure_init.sh

# 3. Open port 8501
az vm open-port \\
    --resource-group cyberwatch-rg \\
    --name cyberwatch-vm \\
    --port 8501

# 4. Get public IP
az vm show \\
    --resource-group cyberwatch-rg \\
    --name cyberwatch-vm \\
    --show-details \\
    --query publicIps \\
    --output tsv
"""

# ── Nginx reverse proxy (optional — for domain + SSL) ────

NGINX_CONF = """\
# /etc/nginx/sites-available/cyberwatch
# Reverse proxy Streamlit behind Nginx with SSL (Let's Encrypt)
# Replace yourdomain.com with your actual domain

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass         http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_read_timeout 86400;
    }
}
"""

# ── Write all files ───────────────────────────────────────

def generate_all():
    files = {
        DEPLOY_DIR.parent / "Dockerfile"             : DOCKERFILE,
        DEPLOY_DIR.parent / "docker-compose.yml"     : DOCKER_COMPOSE,
        DEPLOY_DIR.parent / "requirements.txt"       : REQUIREMENTS,
        DEPLOY_DIR        / "aws_userdata.sh"         : AWS_USERDATA,
        DEPLOY_DIR        / "aws_commands.sh"         : AWS_SECURITY_GROUP,
        DEPLOY_DIR        / "gcp_startup.sh"          : GCP_STARTUP,
        DEPLOY_DIR        / "gcp_commands.sh"         : GCP_GCLOUD,
        DEPLOY_DIR        / "azure_init.sh"           : AZURE_INIT,
        DEPLOY_DIR        / "azure_commands.sh"       : AZURE_CLI,
        DEPLOY_DIR        / "nginx.conf"              : NGINX_CONF,
    }

    DEPLOY_DIR.mkdir(parents=True, exist_ok=True)

    for path, content in files.items():
        path.write_text(content)
        print(f"✅  Generated: {path}")

    print("""
╔══════════════════════════════════════════════╗
║   CyberWatch — Cloud Deployment Ready        ║
╠══════════════════════════════════════════════╣
║                                              ║
║  Docker (any cloud):                         ║
║    docker-compose up -d --build              ║
║    → http://localhost:8501                   ║
║                                              ║
║  AWS:   see deploy/aws_commands.sh           ║
║  GCP:   see deploy/gcp_commands.sh           ║
║  Azure: see deploy/azure_commands.sh         ║
║                                              ║
║  With domain+SSL: see deploy/nginx.conf      ║
╚══════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    generate_all()
