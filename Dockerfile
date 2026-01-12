FROM mcr.microsoft.com/playwright:v1.40.0-jammy
WORKDIR /app

RUN mkdir -p ./data/screenshots ./data/repos /root/.codex/sessions

RUN npm install -g @fuzzland/tintin @openai/codex @anthropic-ai/claude-code

CMD ["/bin/bash", "-c", "\
    node -e \"require('fs').writeFileSync('config.toml', process.env.TINTIN_CONFIG)\" && \
    echo '' && \
    echo '========== VERIFICATION CONFIG ==========' && \
    cat config.toml && \
    echo '==========================================' && \
    echo '' && \
    echo \"OPENAI_API_KEY is set: ${OPENAI_API_KEY:+YES}\" && \
    tintin start && sleep 3 && tail -f /app/data/tintin.log \
"]
