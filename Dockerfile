# Utiliser Python 3.11 slim pour réduire la taille
FROM python:3.11-slim

# Définir les variables d'environnement
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Outils de base
    curl \
    wget \
    gnupg \
    ca-certificates \
    git \
    # Dépendances pour Playwright/Chromium
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    libu2f-udev \
    libvulkan1 \
    # Dépendances pour codex
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Installer Node.js 20.x (requis pour npx et Playwright MCP)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de l'application
WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Installer Playwright et ses dépendances
RUN npx -y playwright@latest install chromium --with-deps

# Installer le serveur MCP Playwright
RUN npm install -g @playwright/mcp@latest

# Copier tout le code de l'application
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p /app/data /app/data/repos /app/data/screenshots /root/.codex/sessions

# Donner les permissions appropriées
RUN chmod +x /app/entrypoint.sh 2>/dev/null || true

# Port exposé
EXPOSE 8787

# Commande de démarrage
CMD ["python", "-u", "main.py"]
