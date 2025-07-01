"""
Configuration settings for the Vulnerability Battle System
"""

import os
from pathlib import Path

# Base configuration
CONFIG = {
    'api_url': "https://api.llmapi.com/chat/completions",
    'api_key': os.environ.get('LLM_API_KEY', ''),  # Must be set as environment variable
    'random_seed': 42,
    'max_concurrent_battles': 2,
    'checkpoint_interval': 3,
    'memory_limit_pct': 90,
    'min_rounds': 3,
    'convergence_window': 4,
    'significance_level': 0.05,
    'consensus_threshold': 0.70,
    'cache_max_size': 200,
    'execution_timeout': 10
}

# Results directory configuration
RESULTS_DIR = os.environ.get('RESULTS_DIR', './vulnerability_research')

# Model configurations with learning parameters
MODEL_CONFIGS = {
    "deepseek": {
        "api": "deepseek-v3",
        "base_timeout": 45,
        "complexity_factor": 1.2,
        "base_temperature": 0.7,
        "learning_rate": 0.15,
        "exploration_bonus": 0.3
    },
    "qwen-72b": {
        "api": "Qwen2-72B",
        "base_timeout": 40,
        "complexity_factor": 1.1,
        "base_temperature": 0.6,
        "learning_rate": 0.12,
        "exploration_bonus": 0.25
    },
    "qwen-7b": {
        "api": "Qwen2.5-7B",
        "base_timeout": 30,
        "complexity_factor": 1.0,
        "base_temperature": 0.8,
        "learning_rate": 0.20,
        "exploration_bonus": 0.4
    },
    "mixtral": {
        "api": "mixtral-8x22b-instruct",
        "base_timeout": 50,
        "complexity_factor": 1.3,
        "base_temperature": 0.5,
        "learning_rate": 0.10,
        "exploration_bonus": 0.2
    },
    "llama": {
        "api": "llama3.1-70b",
        "base_timeout": 45,
        "complexity_factor": 1.15,
        "base_temperature": 0.65,
        "learning_rate": 0.13,
        "exploration_bonus": 0.28
    }
}

# Create results directory if it doesn't exist
Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)
