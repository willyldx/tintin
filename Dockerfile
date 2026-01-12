FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# CORRECTION : On utilise Node.js pour écrire le fichier de config.
# Cela préserve parfaitement les guillemets et les caractères spéciaux.
CMD node -e 'require("fs").writeFileSync("config.toml", process.env.TINTIN_CONFIG)' && tintin start && sleep 3 && tail -f /app/data/tintin.log
