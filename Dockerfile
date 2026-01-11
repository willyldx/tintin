FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# Correction : On lance Tintin ET on affiche les logs en continu.
# Le "tail -f" force le conteneur à rester ouvert indéfiniment.
CMD echo "$TINTIN_CONFIG" > config.toml && tintin start && sleep 3 && tail -f /app/data/tintin.log
