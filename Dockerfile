FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# VERSION DIAGNOSTIC
# 1. Crée le fichier
# 2. L'affiche dans les logs pour qu'on puisse vérifier (cat config.toml)
# 3. Lance le bot
CMD node -e 'require("fs").writeFileSync("config.toml", process.env.TINTIN_CONFIG)' && \
    echo "\n========== VERIFICATION CONFIG ==========" && \
    cat config.toml && \
    echo "=========================================\n" && \
    tintin start && sleep 3 && tail -f /app/data/tintin.log
