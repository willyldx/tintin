# mcp_fix.py - Correction pour l'authentification MCP Playwright
import os
import subprocess
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def start_mcp_server():
    """Démarre le serveur MCP Playwright avec les bonnes configurations"""
    
    # Vérifier que la clé API OpenAI est disponible
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("OPENAI_API_KEY non définie !")
        return None
    
    logger.info("Démarrage du serveur MCP Playwright...")
    
    # Définir les variables d'environnement pour MCP
    mcp_env = os.environ.copy()
    mcp_env.update({
        "OPENAI_API_KEY": api_key,
        "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
        "NODE_ENV": "production"
    })
    
    try:
        # Démarrer le serveur MCP
        process = subprocess.Popen(
            [
                "npx",
                "@playwright/mcp@latest",
                "--headless",
                "--browser", "chromium",
                "--port", "11000"
            ],
            env=mcp_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Attendre que le serveur démarre
        time.sleep(5)
        
        if process.poll() is None:
            logger.info("✅ Serveur MCP démarré avec succès sur le port 11000")
            return process
        else:
            stderr = process.stderr.read()
            logger.error(f"❌ Erreur lors du démarrage MCP: {stderr}")
            return None
            
    except Exception as e:
        logger.error(f"❌ Exception lors du démarrage MCP: {e}")
        return None

if __name__ == "__main__":
    start_mcp_server()
