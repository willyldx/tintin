FROM mcr.microsoft.com/playwright:v1.40.0-jammy
WORKDIR /app

RUN mkdir -p ./data/screenshots ./data/repos /root/.codex/sessions

RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

CMD sh -c '\
    node -e "require(\"fs\").writeFileSync(\"config.toml\", process.env.TINTIN_CONFIG)" && \
    echo "\n========== VERIFICATION CONFIG ==========" && \
    cat config.toml && \
    echo "\n========== OPENAI_API_KEY: ${OPENAI_API_KEY:0:20}... ==========" && \
    echo "=========================================\n" && \
    export OPENAI_API_KEY="${OPENAI_API_KEY}" && \
    tintin start && sleep 3 && tail -f /app/data/tintin.log'
