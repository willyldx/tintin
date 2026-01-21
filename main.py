import os
import sys
import logging
from dotenv import load_dotenv

# Charger les variables d'environnement depuis .env (pour dev local)
load_dotenv()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Vérifier les variables d'environnement critiques
def check_environment():
    """Vérifie que toutes les variables d'environnement requises sont présentes"""
    required_vars = {
        "OPENAI_API_KEY": "Clé API OpenAI",
        "TELEGRAM_BOT_TOKEN": "Token du bot Telegram"
    }
    
    missing = []
    for var, description in required_vars.items():
        value = os.getenv(var)
        if not value:
            missing.append(f"{var} ({description})")
            logger.error(f"❌ {var} manquante !")
        else:
            # Afficher seulement les premiers et derniers caractères
            masked = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else "***"
            logger.info(f"✅ {var}: {masked}")
    
    if missing:
        logger.error(f"Variables d'environnement manquantes: {', '.join(missing)}")
        logger.error("Configurez-les dans Railway ou dans votre fichier .env")
        sys.exit(1)

# Appeler la vérification au démarrage
check_environment()

# Le reste de votre code main.py...
