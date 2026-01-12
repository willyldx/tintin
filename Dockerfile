FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

# Installation des dépendances
RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# CORRECTION CRITIQUE :
# On utilise Node.js (fs.writeFileSync) pour créer le fichier config.toml.
# Contrairement à 'echo', cela préserve PARFAITEMENT les guillemets et la syntaxe.
CMD node -e 'require("fs").writeFileSync("config.toml", process.env.TINTIN_CONFIG)' && tintin start && sleep 3 && tail -f /app/data/tintin.log
