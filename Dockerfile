FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

# C'EST ICI QUE TOUT SE JOUE :
# On utilise Node.js pour écrire le fichier. C'est la seule façon qui marche à coup sûr.
CMD node -e 'require("fs").writeFileSync("config.toml", process.env.TINTIN_CONFIG)' && tintin start && sleep 3 && tail -f /app/data/tintin.log
