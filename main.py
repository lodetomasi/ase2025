#!/usr/bin/env python3
"""
Main entry point for the Vulnerability Battle System
"""

import os
import sys
import argparse
import logging
from typing import List

from core.battle_manager import IntelligentBattleManager
from analysis.tournament import TournamentOrganizer


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('vulnerability_battle.log')
        ]
    )


def run_single_battle(attacker: str, defender: str, vulnerability: str, rounds: int = 15):
    """Run a single battle between two models"""
    print(f"\nRunning single battle: {attacker} vs {defender} on {vulnerability}")
    
    manager = IntelligentBattleManager()
    result = manager.run_battle(
        attacker_model=attacker,
        defender_model=defender,
        vulnerability_type=vulnerability,
        max_rounds=rounds
    )
    
    print("\nBattle Result:")
    print(f"Winner: {result.get('winner', 'unknown')}")
    print(f"Total rounds: {result.get('total_rounds', 0)}")
    print(f"Attacker wins: {result.get('attacker_wins', 0)}")
    print(f"Defender wins: {result.get('defender_wins', 0)}")
    
    return result


def run_tournament(models: List[str], vulnerabilities: List[str], rounds_per_battle: int = 12):
    """Run a full tournament"""
    print(f"\nRunning tournament with {len(models)} models and {len(vulnerabilities)} vulnerabilities")
    
    organizer = TournamentOrganizer()
    results = organizer.run_tournament(
        models=models,
        vulnerabilities=vulnerabilities,
        rounds_per_battle=rounds_per_battle
    )
    
    return results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Vulnerability Battle System with Thompson Sampling')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Single battle command
    battle_parser = subparsers.add_parser('battle', help='Run a single battle')
    battle_parser.add_argument('attacker', choices=['qwen-7b', 'qwen-72b', 'deepseek', 'mixtral', 'llama'],
                             help='Attacker model')
    battle_parser.add_argument('defender', choices=['qwen-7b', 'qwen-72b', 'deepseek', 'mixtral', 'llama'],
                             help='Defender model')
    battle_parser.add_argument('vulnerability', 
                             choices=['CWE-78', 'CWE-89', 'CWE-79', 'CWE-22', 'CWE-502', 'CWE-327', 'CWE-798'],
                             help='Vulnerability type')
    battle_parser.add_argument('--rounds', type=int, default=15, help='Maximum rounds (default: 15)')
    
    # Tournament command
    tournament_parser = subparsers.add_parser('tournament', help='Run a tournament')
    tournament_parser.add_argument('--models', nargs='+', 
                                 default=['qwen-7b', 'deepseek', 'llama'],
                                 choices=['qwen-7b', 'qwen-72b', 'deepseek', 'mixtral', 'llama'],
                                 help='Models to include in tournament')
    tournament_parser.add_argument('--vulnerabilities', nargs='+',
                                 default=['CWE-78', 'CWE-89', 'CWE-79'],
                                 choices=['CWE-78', 'CWE-89', 'CWE-79', 'CWE-22', 'CWE-502', 'CWE-327', 'CWE-798'],
                                 help='Vulnerabilities to test')
    tournament_parser.add_argument('--rounds', type=int, default=12, 
                                 help='Rounds per battle (default: 12)')
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--api-key', help='API key (can also use LLM_API_KEY env var)')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Set API key if provided
    if args.api_key:
        os.environ['LLM_API_KEY'] = args.api_key
    
    # Check API key
    if not os.environ.get('LLM_API_KEY'):
        print("Error: No API key found. Please set LLM_API_KEY environment variable or use --api-key")
        print("Example: export LLM_API_KEY='your-api-key-here'")
        sys.exit(1)
    
    # Execute command
    if args.command == 'battle':
        run_single_battle(args.attacker, args.defender, args.vulnerability, args.rounds)
    elif args.command == 'tournament':
        run_tournament(args.models, args.vulnerabilities, args.rounds)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()