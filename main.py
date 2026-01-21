import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ============================================
# CONFIGURATION DEPUIS VARIABLES D'ENVIRONNEMENT
# ============================================

class Config:
    """Configuration chargée depuis les variables d'environnement"""
    
    # Bot
    BOT_NAME = os.getenv("BOT_NAME", "tintin-bot")
    BOT_HOST = os.getenv("BOT_HOST", "0.0.0.0")
    BOT_PORT = int(os.getenv("BOT_PORT", "8787"))
    DATA_DIR = os.getenv("DATA_DIR", "./data")
    GITHUB_REPOS_DIR = os.getenv("GITHUB_REPOS_DIR", "./data/repos")
    
    # Database
    DB_URL = os.getenv("DB_URL", "sqlite+aiosqlite:///./data/tintin-bot.db")
    DB_ECHO = os.getenv("DB_ECHO", "false").lower() == "true"
    
    # Security
    RESTRICT_PATHS = os.getenv("RESTRICT_PATHS", "false").lower() == "true"
    TELEGRAM_ALLOW_USER_IDS = [int(x) for x in os.getenv("TELEGRAM_ALLOW_USER_IDS", "1331871487").split(",")]
    TELEGRAM_ALLOW_CHAT_IDS = [int(x) for x in os.getenv("TELEGRAM_ALLOW_CHAT_IDS", "-1003565601374,1331871487").split(",")]
    
    # API Keys (REQUIS)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    
    # Codex
    CODEX_BINARY = os.getenv("CODEX_BINARY", "codex")
    CODEX_LOG_LEVEL = os.getenv("CODEX_LOG_LEVEL", "debug")
    CODEX_MESSAGE_VERBOSITY = int(os.getenv("CODEX_MESSAGE_VERBOSITY", "2"))
    CODEX_SESSIONS_DIR = os.getenv("CODEX_SESSIONS_DIR", "~/.codex/sessions")
    CODEX_POLL_INTERVAL_MS = int(os.getenv("CODEX_POLL_INTERVAL_MS", "500"))
    CODEX_TIMEOUT_SECONDS = int(os.getenv("CODEX_TIMEOUT_SECONDS", "3600"))
    
    # Telegram
    TELEGRAM_MODE = os.getenv("TELEGRAM_MODE", "poll")
    TELEGRAM_POLL_TIMEOUT = int(os.getenv("TELEGRAM_POLL_TIMEOUT", "30"))
    TELEGRAM_USE_TOPICS = os.getenv("TELEGRAM_USE_TOPICS", "true").lower() == "true"
    TELEGRAM_MAX_CHARS = int(os.getenv("TELEGRAM_MAX_CHARS", "3500"))
    
    # Playwright MCP
    PLAYWRIGHT_ENABLED = os.getenv("PLAYWRIGHT_ENABLED", "true").lower() == "true"
    PLAYWRIGHT_HEADLESS = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"
    PLAYWRIGHT_OUTPUT_DIR = os.getenv("PLAYWRIGHT_OUTPUT_DIR", "./data/screenshots")
    PLAYWRIGHT_BROWSER = os.getenv("PLAYWRIGHT_BROWSER", "chromium")
    PLAYWRIGHT_NO_SANDBOX = os.getenv("PLAYWRIGHT_NO_SANDBOX", "true").lower() == "true"
    PLAYWRIGHT_BROWSERS_PATH = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright")
    
    # Auto-migration
    BOT_AUTO_MIGRATE = os.getenv("BOT_AUTO_MIGRATE", "true").lower() == "true"
    CODEX_TELEMETRY = os.getenv("CODEX_TELEMETRY", "0")

def check_required_env_vars():
    """Vérifie que toutes les variables d'environnement requises sont présentes"""
    required = {
        "OPENAI_API_KEY": Config.OPENAI_API_KEY,
        "TELEGRAM_BOT_TOKEN": Config.TELEGRAM_BOT_TOKEN
    }
    
    missing = []
    for name, value in required.items():
        if not value:
            missing.append(name)
            logger.error(f"❌ Variable d'environnement manquante: {name}")
        else:
            masked = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else "***"
            logger.info(f"✅ {name}: {masked}")
    
    if missing:
        logger.error(f"⚠️ Configurez ces variables dans Railway: {', '.join(missing)}")
        sys.exit(1)
    
    logger.info("✅ Toutes les variables d'environnement requises sont présentes")

# Vérifier au démarrage
check_required_env_vars()

# Votre code utilise maintenant Config.OPENAI_API_KEY, Config.TELEGRAM_BOT_TOKEN, etc.
