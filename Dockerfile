FROM mcr.microsoft.com/playwright:v1.40.0-jammy
WORKDIR /app

# Créer les dossiers nécessaires
RUN mkdir -p ./data/screenshots ./data/repos /root/.codex/sessions

# Installer les dépendances
RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# Lancer le bot
CMD node -e 'require("fs").writeFileSync("config.toml", process.env.TINTIN_CONFIG)' && \
    echo "\n========== VERIFICATION CONFIG ==========" && \
    cat config.toml && \
    echo "=========================================\n" && \
    tintin start && sleep 3 && tail -f /app/data/tintin.log
