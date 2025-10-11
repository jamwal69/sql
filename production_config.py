"""
Production Configuration Loader for RimTyres AI Agent

Supports multiple deployment platforms:
- Railway (recommended)
- Render
- Docker (with secrets or env vars)
- Vercel
- Any platform with environment variables

Security features:
- No hardcoded credentials
- Multiple config sources (priority order)
- Validation & error handling
- Development fallback
"""

import os
from pathlib import Path
from typing import Dict, Optional

class ProductionConfig:
    """Load configuration from multiple sources with priority"""
    
    def __init__(self):
        self.config = {}
        self.source = None
        self._load_config()
    
    def _load_config(self):
        """
        Load configuration from sources (priority order):
        1. Docker secrets (/run/secrets/*)
        2. Environment variables (Railway, Render, etc.)
        3. .env file (development only - not recommended for production)
        """
        
        # Try Docker secrets first (most secure)
        if self._load_from_docker_secrets():
            return
        
        # Try environment variables (Railway, Render, etc.)
        if self._load_from_environment():
            return
        
        # Fall back to .env file (development only)
        if self._load_from_env_file():
            return
        
        # No configuration found
        raise ValueError(
            "No Wix credentials found!\n"
            "For production: Set environment variables in your platform dashboard\n"
            "For development: Create .env file with WIX_API_KEY, WIX_SITE_ID, WIX_ACCOUNT_ID"
        )
    
    def _load_from_docker_secrets(self) -> bool:
        """Load from Docker secrets (/run/secrets/*)"""
        secrets_dir = Path('/run/secrets')
        
        if not secrets_dir.exists():
            return False
        
        try:
            api_key_file = secrets_dir / 'wix_api_key'
            site_id_file = secrets_dir / 'wix_site_id'
            account_id_file = secrets_dir / 'wix_account_id'
            
            if not all([api_key_file.exists(), site_id_file.exists(), account_id_file.exists()]):
                return False
            
            self.config = {
                'api_key': api_key_file.read_text().strip(),
                'site_id': site_id_file.read_text().strip(),
                'account_id': account_id_file.read_text().strip()
            }
            self.source = 'docker_secrets'
            print("✅ Configuration loaded from Docker secrets")
            return True
            
        except Exception as e:
            print(f"⚠️ Failed to load Docker secrets: {e}")
            return False
    
    def _load_from_environment(self) -> bool:
        """Load from environment variables (Railway, Render, etc.)"""
        api_key = os.getenv('WIX_API_KEY')
        site_id = os.getenv('WIX_SITE_ID')
        account_id = os.getenv('WIX_ACCOUNT_ID')
        
        if not all([api_key, site_id, account_id]):
            return False
        
        self.config = {
            'api_key': api_key,
            'site_id': site_id,
            'account_id': account_id
        }
        self.source = 'environment'
        print("✅ Configuration loaded from environment variables")
        return True
    
    def _load_from_env_file(self) -> bool:
        """Load from .env file (development only)"""
        env_file = Path('.env')
        
        if not env_file.exists():
            return False
        
        try:
            from dotenv import load_dotenv
            load_dotenv()
            
            api_key = os.getenv('WIX_API_KEY')
            site_id = os.getenv('WIX_SITE_ID')
            account_id = os.getenv('WIX_ACCOUNT_ID')
            
            if not all([api_key, site_id, account_id]):
                return False
            
            self.config = {
                'api_key': api_key,
                'site_id': site_id,
                'account_id': account_id
            }
            self.source = 'env_file'
            print("⚠️ Configuration loaded from .env file (development mode)")
            print("   For production, use environment variables instead!")
            return True
            
        except ImportError:
            print("⚠️ python-dotenv not installed. Install with: pip install python-dotenv")
            return False
        except Exception as e:
            print(f"⚠️ Failed to load .env file: {e}")
            return False
    
    def get(self, key: str, default=None) -> Optional[str]:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def validate(self) -> bool:
        """Validate that all required credentials are present"""
        required = ['api_key', 'site_id', 'account_id']
        missing = [k for k in required if not self.config.get(k)]
        
        if missing:
            print(f"❌ Missing credentials: {', '.join(missing)}")
            return False
        
        # Basic validation (check format)
        api_key = self.config['api_key']
        if len(api_key) < 10:
            print("❌ API key seems too short. Check your configuration.")
            return False
        
        print("✅ All credentials validated")
        return True
    
    def mask_sensitive_data(self, value: str, show_chars: int = 4) -> str:
        """Mask sensitive data for logging"""
        if not value or len(value) <= show_chars:
            return "****"
        return f"{'*' * (len(value) - show_chars)}{value[-show_chars:]}"
    
    def get_info(self) -> Dict[str, str]:
        """Get configuration info (safe for logging)"""
        return {
            'source': self.source,
            'api_key': self.mask_sensitive_data(self.config.get('api_key', '')),
            'site_id': self.config.get('site_id', 'not_set'),
            'account_id': self.config.get('account_id', 'not_set'),
            'environment': os.getenv('ENVIRONMENT', 'development')
        }


# Global instance - load once at startup
_config_instance = None

def get_production_config() -> ProductionConfig:
    """Get or create production config singleton"""
    global _config_instance
    
    if _config_instance is None:
        _config_instance = ProductionConfig()
        
        # Validate configuration
        if not _config_instance.validate():
            raise ValueError("Invalid Wix credentials configuration")
    
    return _config_instance


def get_wix_credentials() -> Dict[str, str]:
    """
    Get Wix credentials for production use
    
    Returns:
        dict: {'api_key': str, 'site_id': str, 'account_id': str}
    
    Raises:
        ValueError: If credentials are not found or invalid
    """
    config = get_production_config()
    return {
        'api_key': config.get('api_key'),
        'site_id': config.get('site_id'),
        'account_id': config.get('account_id')
    }


# Convenience function for quick access
def get_config_value(key: str, default=None) -> Optional[str]:
    """Get a specific configuration value"""
    config = get_production_config()
    return config.get(key, default)


# For testing
if __name__ == "__main__":
    print("\n" + "="*60)
    print("Testing Production Configuration")
    print("="*60 + "\n")
    
    try:
        config = get_production_config()
        info = config.get_info()
        
        print("Configuration Information:")
        print(f"  Source: {info['source']}")
        print(f"  API Key: {info['api_key']}")
        print(f"  Site ID: {info['site_id']}")
        print(f"  Account ID: {info['account_id']}")
        print(f"  Environment: {info['environment']}")
        
        print("\n✅ Configuration loaded successfully!")
        
        # Test credential retrieval
        print("\nTesting credential retrieval...")
        creds = get_wix_credentials()
        print(f"  API Key length: {len(creds['api_key'])} characters")
        print(f"  Site ID: {creds['site_id']}")
        print(f"  Account ID: {creds['account_id']}")
        
        print("\n✅ All tests passed! Ready for production.")
        
    except Exception as e:
        print(f"\n❌ Configuration error: {e}")
        print("\nFor production deployment:")
        print("  1. Railway: railway variables set WIX_API_KEY='...'")
        print("  2. Render: Add in dashboard under 'Environment'")
        print("  3. Docker: Set in docker-compose.yml or .env file")
        print("\nFor development:")
        print("  Create .env file with:")
        print("    WIX_API_KEY=your-api-key")
        print("    WIX_SITE_ID=your-site-id")
        print("    WIX_ACCOUNT_ID=your-account-id")
