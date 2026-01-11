# On utilise l'image Playwright
FROM mcr.microsoft.com/playwright:v1.40.0-jammy

# Dossier de travail
WORKDIR /app

# Installation de Tintin et des cerveaux
RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# Commande de démarrage simplifiée (forme Shell)
# Cette syntaxe protège mieux les guillemets de la variable
CMD echo "$TINTIN_CONFIG" > config.toml && tintin start
