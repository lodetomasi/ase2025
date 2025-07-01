#!/usr/bin/env python3
"""
Main entry point for the Vulnerability Battle System
"""

import argparse
import sys
import logging
from typing import List

from config import CONFIG
from battle.tournament import TournamentOrganizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('vulnerability_battle.log')
    ]
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='LLM Vulnerability Battle System with Thompson Sampling'
    )
    
    parser.add_argument(
        '--models',
        nargs='+',
        default=['qwen-7b', 'deepseek', 'llama'],
        help='List of models to test'
    )
    
    parser.add_argument(
        '--vulnerabilities',
        nargs='+',
        default=['CWE-78', 'CWE-89', 'CWE-79', 'CWE-22', 'CWE-502'],
        help='List of vulnerability types to test'
    )
    
    parser.add_argument(
        '--rounds',
        type=int,
        default=10,
        help='Number of rounds per battle'
    )
    
    parser.add_argument(
        '--api-key',
        help='API key (can also be set via LLM_API_KEY environment variable)'
    )
    
    return parser.parse_args()


def validate_configuration(args):
    """Validate configuration and environment"""
    # Check API key
    if args.api_key:
        CONFIG['api_key'] = args.api_key
    
    if not CONFIG['api_key']:
        logger.error("No API key provided. Set LLM_API_KEY environment variable or use --api-key")
        return False
    
    # Validate models
    from config import MODEL_CONFIGS
    invalid_models = [m for m in args.models if m not in MODEL_CONFIGS]
    if invalid_models:
        logger.error(f"Invalid models: {invalid_models}")
        logger.info(f"Available models: {list(MODEL_CONFIGS.keys())}")
        return False
    
    # Validate vulnerabilities
    from vulnerabilities.cwe_database import CWE_VULNERABILITIES
    invalid_vulns = [v for v in args.vulnerabilities if v not in CWE_VULNERABILITIES]
    if invalid_vulns:
        logger.error(f"Invalid vulnerabilities: {invalid_vulns}")
        logger.info(f"Available vulnerabilities: {list(CWE_VULNERABILITIES.keys())}")
        return False
    
    return True


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Validate configuration
    if not validate_configuration(args):
        sys.exit(1)
    
    # Log configuration
    logger.info("="*80)
    logger.info("Vulnerability Battle System Starting")
    logger.info(f"Models: {args.models}")
    logger.info(f"Vulnerabilities: {args.vulnerabilities}")
    logger.info(f"Rounds per battle: {args.rounds}")
    logger.info("="*80)
    
    # Run tournament
    try:
        organizer = TournamentOrganizer()
        results = organizer.run_tournament(
            models=args.models,
            vulnerabilities=args.vulnerabilities,
            rounds_per_battle=args.rounds
        )
        
        # Print summary
        print_tournament_summary(results)
        
    except KeyboardInterrupt:
        logger.info("\nTournament interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Tournament failed: {e}", exc_info=True)
        sys.exit(1)


def print_tournament_summary(results):
    """Print tournament summary"""
    print("\n" + "="*80)
    print("TOURNAMENT SUMMARY")
    print("="*80)
    
    if 'final_analysis' in results and results['final_analysis']:
        analysis = results['final_analysis']
        
        print("\nModel Rankings:")
        if 'model_rankings' in analysis:
            for i, (model, score) in enumerate(analysis['model_rankings'], 1):
                print(f"{i}. {model}: {score['score']} points (Win rate: {score['win_rate']:.1%})")
        
        if 'best_attacker' in analysis:
            print(f"\nBest Attacker: {analysis['best_attacker']}")
        if 'best_defender' in analysis:
            print(f"Best Defender: {analysis['best_defender']}")
        if 'most_difficult_vulnerability' in analysis:
            print(f"Most Difficult Vulnerability: {analysis['most_difficult_vulnerability']}")
        if 'easiest_vulnerability' in analysis:
            print(f"Easiest Vulnerability: {analysis['easiest_vulnerability']}")
        
        if 'thompson_sampling_effectiveness' in analysis:
            ts_data = analysis['thompson_sampling_effectiveness']
            print(f"\nThompson Sampling Performance:")
            print(f"  Average convergence time: {ts_data.get('average_convergence_time', 0):.1f} rounds")
            print(f"  Average performance improvement: {ts_data.get('performance_improvement', 0):.1%}")
            print(f"  Average strategy diversity: {ts_data.get('average_strategy_diversity', 0):.1f}")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    main()
