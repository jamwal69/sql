"""
Helper script to load environment variables from .env file
"""
import os
from pathlib import Path


def load_env():
    """Load environment variables from .env file"""
    env_path = Path(__file__).parent / '.env'
    
    if not env_path.exists():
        print("Warning: .env file not found!")
        return
    
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse key=value
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                os.environ[key] = value


if __name__ == "__main__":
    load_env()
    print("Environment variables loaded!")
    print(f"OPENROUTER_API_KEY: {'*' * 20 if os.getenv('OPENROUTER_API_KEY') else 'NOT SET'}")
