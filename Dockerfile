# On part d'une image qui a déjà les dépendances pour les navigateurs (Playwright)
FROM mcr.microsoft.com/playwright:v1.40.0-jammy

# Installation des outils nécessaires
WORKDIR /app

# 1. On installe Tintin (la version officielle stable)
RUN npm install -g @fuzzland/tintin

# 2. On installe les "cerveaux" (Codex et Claude) pour qu'ils soient accessibles
RUN npm install -g @openai/codex @anthropic-ai/claude-code

# 3. Commande de démarrage
# L'astuce : on crée le fichier de config à partir d'une variable Railway au démarrage
CMD sh -c "echo \"$TINTIN_CONFIG\" > config.toml && tintin start"
