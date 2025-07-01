"""
Tournament organization and analysis
"""

import os
import json
import time
import datetime
import gc
import logging
from collections import defaultdict
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from core.battle_manager import IntelligentBattleManager
from core.models import BattleMetrics

logger = logging.getLogger(__name__)


class TournamentOrganizer:
    """Organize and run tournaments"""

    def __init__(self):
        self.battle_manager = IntelligentBattleManager()
        self.results_dir = None

    def run_tournament(self, models: List[str], vulnerabilities: List[str],
                      rounds_per_battle: int = 12) -> Dict[str, Any]:
        """Run a complete tournament"""

        # Create results directory
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = os.path.join("./vulnerability_research", f"tournament_{timestamp}")
        os.makedirs(self.results_dir, exist_ok=True)

        print(f"\n{'='*80}")
        print(f"TOURNAMENT STARTING")
        print(f"Models: {models}")
        print(f"Vulnerabilities: {vulnerabilities}")
        print(f"Rounds per battle: {rounds_per_battle}")
        print(f"Results directory: {self.results_dir}")
        print(f"{'='*80}\n")

        tournament_results = {
            'models': models,
            'vulnerabilities': vulnerabilities,
            'battles': [],
            'model_rankings': defaultdict(lambda: {'wins': 0, 'losses': 0, 'draws': 0}),
            'vulnerability_analysis': defaultdict(lambda: defaultdict(int)),
            'strategy_effectiveness': defaultdict(lambda: defaultdict(list)),
            'learning_analysis': {},
            'timestamp': timestamp
        }

        # Run all battles
        total_battles = len(models) * (len(models) - 1) * len(vulnerabilities)
        battle_count = 0

        for vuln in vulnerabilities:
            for attacker in models:
                for defender in models:
                    if attacker != defender:
                        battle_count += 1
                        print(f"\n[Battle {battle_count}/{total_battles}]")

                        # Run battle
                        battle_result = self.battle_manager.run_battle(
                            attacker, defender, vuln, rounds_per_battle,
                            checkpoint_dir=self.results_dir
                        )

                        # Record results
                        tournament_results['battles'].append(battle_result)

                        # Update rankings
                        if battle_result['winner'] == 'attacker':
                            tournament_results['model_rankings'][attacker]['wins'] += 1
                            tournament_results['model_rankings'][defender]['losses'] += 1
                        elif battle_result['winner'] == 'defender':
                            tournament_results['model_rankings'][defender]['wins'] += 1
                            tournament_results['model_rankings'][attacker]['losses'] += 1
                        else:
                            tournament_results['model_rankings'][attacker]['draws'] += 1
                            tournament_results['model_rankings'][defender]['draws'] += 1

                        # Update vulnerability analysis
                        tournament_results['vulnerability_analysis'][vuln][battle_result['winner']] += 1

                        # Save intermediate results
                        self._save_tournament_results(tournament_results)

                        # Memory cleanup
                        gc.collect()

        # Final analysis
        tournament_results['final_analysis'] = self._analyze_tournament_results(tournament_results)

        # Save final results
        self._save_tournament_results(tournament_results)
        self._generate_visualizations(tournament_results)

        print(f"\n{'='*80}")
        print("TOURNAMENT COMPLETE")
        print(f"Results saved to: {self.results_dir}")
        print(f"{'='*80}\n")

        return tournament_results

    def _analyze_tournament_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive tournament analysis"""

        # Model performance analysis
        model_scores = {}
        for model, record in results['model_rankings'].items():
            total_battles = record['wins'] + record['losses'] + record['draws']
            if total_battles > 0:
                win_rate = record['wins'] / total_battles
                # Score calculation: wins=3, draws=1, losses=0
                score = record['wins'] * 3 + record['draws']
                model_scores[model] = {
                    'score': score,
                    'win_rate': win_rate,
                    'total_battles': total_battles
                }

        # Rank models
        ranked_models = sorted(model_scores.items(), key=lambda x: x[1]['score'], reverse=True)

        # Vulnerability difficulty analysis
        vuln_difficulty = {}
        for vuln, outcomes in results['vulnerability_analysis'].items():
            total = sum(outcomes.values())
            if total > 0:
                attacker_success_rate = outcomes.get('attacker', 0) / total
                vuln_difficulty[vuln] = {
                    'attacker_success_rate': attacker_success_rate,
                    'defender_success_rate': outcomes.get('defender', 0) / total,
                    'draw_rate': outcomes.get('draw', 0) / total,
                    'total_battles': total
                }

        # Strategy evolution analysis
        strategy_evolution = self._analyze_strategy_evolution(results['battles'])

        # Thompson Sampling effectiveness
        thompson_effectiveness = self._analyze_thompson_sampling_effectiveness(results['battles'])

        return {
            'model_rankings': ranked_models,
            'model_scores': model_scores,
            'vulnerability_difficulty': vuln_difficulty,
            'strategy_evolution': strategy_evolution,
            'thompson_sampling_effectiveness': thompson_effectiveness,
            'best_attacker': ranked_models[0][0] if ranked_models else None,
            'best_defender': self._find_best_defender(results['battles']),
            'most_difficult_vulnerability': max(vuln_difficulty.items(),
                                             key=lambda x: x[1]['defender_success_rate'])[0] if vuln_difficulty else None,
            'easiest_vulnerability': max(vuln_difficulty.items(),
                                       key=lambda x: x[1]['attacker_success_rate'])[0] if vuln_difficulty else None
        }

    def _analyze_strategy_evolution(self, battles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how strategies evolved during tournament"""

        strategy_timeline = defaultdict(lambda: defaultdict(list))

        for battle in battles:
            if 'strategy_effectiveness' in battle:
                for role in ['attacker', 'defender']:
                    if role in battle['strategy_effectiveness']:
                        for strategy, stats in battle['strategy_effectiveness'][role].items():
                            strategy_timeline[role][strategy].append(stats['success_rate'])

        # Calculate trends
        strategy_trends = {}
        for role, strategies in strategy_timeline.items():
            strategy_trends[role] = {}
            for strategy, success_rates in strategies.items():
                if len(success_rates) >= 3:
                    # Simple linear regression for trend
                    x = np.arange(len(success_rates))
                    y = np.array(success_rates)
                    if len(x) > 1:
                        slope, _ = np.polyfit(x, y, 1)
                        strategy_trends[role][strategy] = {
                            'trend': 'improving' if slope > 0.01 else 'declining' if slope < -0.01 else 'stable',
                            'slope': slope,
                            'final_rate': success_rates[-1] if success_rates else 0
                        }

        return strategy_trends

    def _analyze_thompson_sampling_effectiveness(self, battles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze Thompson Sampling effectiveness"""

        convergence_times = []
        final_performances = []
        strategy_diversity = []

        for battle in battles:
            if 'thompson_sampling_convergence' in battle:
                # Extract convergence metrics
                for role in ['attacker', 'defender']:
                    if role in battle['thompson_sampling_convergence']:
                        conv_data = battle['thompson_sampling_convergence'][role]

                        # Convergence time (rounds to reach stable strategy)
                        if 'total_rounds' in conv_data:
                            convergence_times.append(conv_data['total_rounds'])

                        # Final performance
                        if 'overall_success_rate' in conv_data:
                            final_performances.append(conv_data['overall_success_rate'])

                        # Strategy diversity
                        if 'strategy_performance' in conv_data:
                            diversity = len([s for s, p in conv_data['strategy_performance'].items()
                                          if p['attempts'] > 0])
                            strategy_diversity.append(diversity)

        return {
            'average_convergence_time': np.mean(convergence_times) if convergence_times else 0,
            'average_final_performance': np.mean(final_performances) if final_performances else 0,
            'average_strategy_diversity': np.mean(strategy_diversity) if strategy_diversity else 0,
            'performance_improvement': self._calculate_performance_improvement(battles)
        }

    def _calculate_performance_improvement(self, battles: List[Dict[str, Any]]) -> float:
        """Calculate average performance improvement from Thompson Sampling"""

        improvements = []

        for battle in battles:
            if 'learning_curves' in battle:
                curves = battle['learning_curves']
                for role in ['attacker_performance', 'defender_performance']:
                    if role in curves and len(curves[role]) >= 2:
                        improvement = curves[role][-1] - curves[role][0]
                        improvements.append(improvement)

        return np.mean(improvements) if improvements else 0.0

    def _find_best_defender(self, battles: List[Dict[str, Any]]) -> Optional[str]:
        """Find the best defensive model"""

        defender_stats = defaultdict(lambda: {'defenses': 0, 'successful_defenses': 0})

        for battle in battles:
            # Extract defender from battle_id
            if 'battle_id' in battle and '_vs_' in battle['battle_id']:
                parts = battle['battle_id'].split('_vs_')
                if len(parts) >= 2:
                    defender = parts[1].split('_')[0]  # Remove vulnerability suffix

                    if battle['winner'] == 'defender':
                        defender_stats[defender]['successful_defenses'] += 1
                    defender_stats[defender]['defenses'] += 1

        # Calculate defense success rates
        defense_rates = {}
        for model, stats in defender_stats.items():
            if stats['defenses'] > 0:
                defense_rates[model] = stats['successful_defenses'] / stats['defenses']

        if defense_rates:
            return max(defense_rates.items(), key=lambda x: x[1])[0]
        return None

    def _save_tournament_results(self, results: Dict[str, Any]):
        """Save tournament results to file"""

        # Save as JSON
        json_path = os.path.join(self.results_dir, "tournament_results.json")
        with open(json_path, 'w') as f:
            # Convert non-serializable objects
            serializable_results = self._make_serializable(results)
            json.dump(serializable_results, f, indent=2)

        # Save as CSV for easy analysis
        self._save_results_as_csv(results)

    def _make_serializable(self, obj):
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, (np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, defaultdict):
            return dict(obj)
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(v) for v in obj]
        elif isinstance(obj, BattleMetrics):
            return obj.to_dict()
        else:
            return obj

    def _save_results_as_csv(self, results: Dict[str, Any]):
        """Save results as CSV files"""

        # Model rankings CSV
        rankings_data = []
        for model, record in results['model_rankings'].items():
            rankings_data.append({
                'Model': model,
                'Wins': record['wins'],
                'Losses': record['losses'],
                'Draws': record['draws'],
                'Total': record['wins'] + record['losses'] + record['draws'],
                'Win_Rate': record['wins'] / max(1, record['wins'] + record['losses'] + record['draws'])
            })

        if rankings_data:
            rankings_df = pd.DataFrame(rankings_data)
            rankings_df.to_csv(os.path.join(self.results_dir, 'model_rankings.csv'), index=False)

        # Battle details CSV
        battle_data = []
        for battle in results['battles']:
            battle_data.append({
                'Battle_ID': battle.get('battle_id', ''),
                'Attacker': battle.get('battle_id', '').split('_vs_')[0] if '_vs_' in battle.get('battle_id', '') else '',
                'Defender': battle.get('battle_id', '').split('_vs_')[1].split('_')[0] if '_vs_' in battle.get('battle_id', '') else '',
                'Vulnerability': battle.get('vulnerability_type', ''),
                'Rounds': battle.get('total_rounds', 0),
                'Winner': battle.get('winner', ''),
                'Attacker_Wins': battle.get('attacker_wins', 0),
                'Defender_Wins': battle.get('defender_wins', 0),
                'Draws': battle.get('draws', 0)
            })

        if battle_data:
            battles_df = pd.DataFrame(battle_data)
            battles_df.to_csv(os.path.join(self.results_dir, 'battle_details.csv'), index=False)

    def _generate_visualizations(self, results: Dict[str, Any]):
        """Generate visualization plots"""

        # Set up plotting style
        plt.style.use('seaborn-v0_8-darkgrid')

        # 1. Model Performance Heatmap
        self._plot_model_performance_heatmap(results)

        # 2. Strategy Evolution Plot
        self._plot_strategy_evolution(results)

        # 3. Vulnerability Difficulty Chart
        self._plot_vulnerability_analysis(results)

        # 4. Thompson Sampling Convergence
        self._plot_thompson_sampling_convergence(results)

        # 5. Win Rate Comparison
        self._plot_win_rate_comparison(results)

    def _plot_model_performance_heatmap(self, results: Dict[str, Any]):
        """Plot model vs model performance heatmap"""

        models = results['models']
        n_models = len(models)

        # Create performance matrix
        performance_matrix = np.zeros((n_models, n_models))

        for battle in results['battles']:
            if '_vs_' in battle.get('battle_id', ''):
                parts = battle['battle_id'].split('_vs_')
                if len(parts) >= 2:
                    attacker = parts[0]
                    defender = parts[1].split('_')[0]  # Remove vulnerability suffix

                    if attacker in models and defender in models:
                        i = models.index(attacker)
                        j = models.index(defender)

                        if battle['winner'] == 'attacker':
                            performance_matrix[i][j] += 1
                        elif battle['winner'] == 'defender':
                            performance_matrix[j][i] += 1

        # Plot heatmap
        plt.figure(figsize=(10, 8))
        sns.heatmap(performance_matrix, annot=True, fmt='.0f',
                   xticklabels=models, yticklabels=models,
                   cmap='RdYlBu_r', center=0)
        plt.title('Model vs Model Win Matrix\n(Row = Attacker, Column = Defender)')
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'model_performance_heatmap.png'), dpi=300)
        plt.close()

    def _plot_strategy_evolution(self, results: Dict[str, Any]):
        """Plot strategy effectiveness evolution"""

        if 'final_analysis' not in results or 'strategy_evolution' not in results['final_analysis']:
            return

        strategy_evolution = results['final_analysis']['strategy_evolution']

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # Attacker strategies
        if 'attacker' in strategy_evolution:
            strategies = []
            trends = []
            colors = []

            for strategy, data in strategy_evolution['attacker'].items():
                strategies.append(strategy)
                trends.append(data.get('slope', 0) * 100)  # Convert to percentage
                colors.append('g' if data.get('trend') == 'improving' else 'r' if data.get('trend') == 'declining' else 'gray')

            ax1.bar(strategies, trends, color=colors)
            ax1.set_title('Attacker Strategy Evolution')
            ax1.set_xlabel('Strategy')
            ax1.set_ylabel('Trend (% per round)')
            ax1.axhline(y=0, color='black', linestyle='-', alpha=0.3)
            ax1.tick_params(axis='x', rotation=45)

        # Defender strategies
        if 'defender' in strategy_evolution:
            strategies = []
            trends = []
            colors = []

            for strategy, data in strategy_evolution['defender'].items():
                strategies.append(strategy)
                trends.append(data.get('slope', 0) * 100)
                colors.append('g' if data.get('trend') == 'improving' else 'r' if data.get('trend') == 'declining' else 'gray')

            ax2.bar(strategies, trends, color=colors)
            ax2.set_title('Defender Strategy Evolution')
            ax2.set_xlabel('Strategy')
            ax2.set_ylabel('Trend (% per round)')
            ax2.axhline(y=0, color='black', linestyle='-', alpha=0.3)
            ax2.tick_params(axis='x', rotation=45)

        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'strategy_evolution.png'), dpi=300)
        plt.close()

    def _plot_vulnerability_analysis(self, results: Dict[str, Any]):
        """Plot vulnerability difficulty analysis"""

        vuln_data = results['vulnerability_analysis']
        if not vuln_data:
            return

        vulnerabilities = list(vuln_data.keys())
        attacker_rates = []
        defender_rates = []

        for vuln in vulnerabilities:
            total = sum(vuln_data[vuln].values())
            if total > 0:
                attacker_rates.append(vuln_data[vuln].get('attacker', 0) / total * 100)
                defender_rates.append(vuln_data[vuln].get('defender', 0) / total * 100)
            else:
                attacker_rates.append(0)
                defender_rates.append(0)

        x = np.arange(len(vulnerabilities))
        width = 0.35

        fig, ax = plt.subplots(figsize=(12, 6))
        bars1 = ax.bar(x - width/2, attacker_rates, width, label='Attacker Success', color='red', alpha=0.7)
        bars2 = ax.bar(x + width/2, defender_rates, width, label='Defender Success', color='blue', alpha=0.7)

        ax.set_xlabel('Vulnerability Type')
        ax.set_ylabel('Success Rate (%)')
        ax.set_title('Vulnerability Difficulty Analysis')
        ax.set_xticks(x)
        ax.set_xticklabels(vulnerabilities, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}%',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=8)

        for bar in bars2:
            height = bar.get_height()
            ax.annotate(f'{height:.1f}%',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=8)

        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'vulnerability_analysis.png'), dpi=300)
        plt.close()

    def _plot_thompson_sampling_convergence(self, results: Dict[str, Any]):
        """Plot Thompson Sampling convergence analysis"""

        if 'final_analysis' not in results:
            return

        thompson_data = results['final_analysis'].get('thompson_sampling_effectiveness', {})

        if not thompson_data:
            return

        # Create a summary plot
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))

        # 1. Convergence time distribution
        convergence_times = []
        for battle in results['battles']:
            if 'total_rounds' in battle:
                convergence_times.append(battle['total_rounds'])

        if convergence_times:
            ax1.hist(convergence_times, bins=15, alpha=0.7, color='green', edgecolor='black')
            ax1.axvline(np.mean(convergence_times), color='red', linestyle='--',
                       label=f'Mean: {np.mean(convergence_times):.1f}')
            ax1.set_xlabel('Rounds to Convergence')
            ax1.set_ylabel('Frequency')
            ax1.set_title('Battle Convergence Distribution')
            ax1.legend()

        # 2. Performance improvement
        improvements = []
        for battle in results['battles']:
            if 'learning_curves' in battle:
                for role in ['attacker_performance', 'defender_performance']:
                    if role in battle['learning_curves'] and len(battle['learning_curves'][role]) >= 2:
                        improvement = (battle['learning_curves'][role][-1] -
                                     battle['learning_curves'][role][0]) * 100
                        improvements.append(improvement)

        if improvements:
            ax2.hist(improvements, bins=20, alpha=0.7, color='blue', edgecolor='black')
            ax2.axvline(0, color='black', linestyle='-', alpha=0.5)
            ax2.axvline(np.mean(improvements), color='red', linestyle='--',
                       label=f'Mean: {np.mean(improvements):.1f}%')
            ax2.set_xlabel('Performance Improvement (%)')
            ax2.set_ylabel('Frequency')
            ax2.set_title('Learning Performance Gains')
            ax2.legend()

        # 3. Strategy diversity over time
        ax3.text(0.5, 0.5, f"Average Strategy Diversity:\n{thompson_data.get('average_strategy_diversity', 0):.1f} strategies",
                ha='center', va='center', fontsize=16, transform=ax3.transAxes)
        ax3.set_title('Strategy Exploration')
        ax3.axis('off')

        # 4. Final performance distribution
        final_performances = []
        for battle in results['battles']:
            if 'thompson_sampling_convergence' in battle:
                for role in ['attacker', 'defender']:
                    if role in battle['thompson_sampling_convergence']:
                        perf = battle['thompson_sampling_convergence'][role].get('overall_success_rate', 0)
                        final_performances.append(perf * 100)

        if final_performances:
            ax4.hist(final_performances, bins=20, alpha=0.7, color='purple', edgecolor='black')
            ax4.axvline(np.mean(final_performances), color='red', linestyle='--',
                       label=f'Mean: {np.mean(final_performances):.1f}%')
            ax4.set_xlabel('Final Success Rate (%)')
            ax4.set_ylabel('Frequency')
            ax4.set_title('Final Performance Distribution')
            ax4.legend()

        plt.suptitle('Thompson Sampling Learning Analysis', fontsize=16)
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'thompson_sampling_analysis.png'), dpi=300)
        plt.close()

    def _plot_win_rate_comparison(self, results: Dict[str, Any]):
        """Plot model win rate comparison"""

        model_data = []
        for model, record in results['model_rankings'].items():
            total = record['wins'] + record['losses'] + record['draws']
            if total > 0:
                model_data.append({
                    'model': model,
                    'win_rate': record['wins'] / total * 100,
                    'loss_rate': record['losses'] / total * 100,
                    'draw_rate': record['draws'] / total * 100
                })

        if not model_data:
            return

        # Sort by win rate
        model_data.sort(key=lambda x: x['win_rate'], reverse=True)

        models = [d['model'] for d in model_data]
        win_rates = [d['win_rate'] for d in model_data]
        loss_rates = [d['loss_rate'] for d in model_data]
        draw_rates = [d['draw_rate'] for d in model_data]

        # Create stacked bar chart
        fig, ax = plt.subplots(figsize=(10, 6))

        x = np.arange(len(models))
        width = 0.6

        p1 = ax.bar(x, win_rates, width, label='Wins', color='green', alpha=0.8)
        p2 = ax.bar(x, draw_rates, width, bottom=win_rates, label='Draws', color='yellow', alpha=0.8)
        p3 = ax.bar(x, loss_rates, width, bottom=np.array(win_rates) + np.array(draw_rates),
                   label='Losses', color='red', alpha=0.8)

        ax.set_ylabel('Percentage (%)')
        ax.set_title('Model Performance Comparison')
        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.legend()
        ax.set_ylim(0, 100)

        # Add percentage labels
        for i, (w, d, l) in enumerate(zip(win_rates, draw_rates, loss_rates)):
            if w > 5:  # Only show label if segment is large enough
                ax.text(i, w/2, f'{w:.1f}%', ha='center', va='center', fontsize=9)
            if d > 5:
                ax.text(i, w + d/2, f'{d:.1f}%', ha='center', va='center', fontsize=9)
            if l > 5:
                ax.text(i, w + d + l/2, f'{l:.1f}%', ha='center', va='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'win_rate_comparison.png'), dpi=300)
        plt.close()


def main():
    """Main entry point for running a tournament"""

    # Select models for tournament
    models = ["qwen-7b", "deepseek", "llama"]

    # Select vulnerabilities to test
    vulnerabilities = ["CWE-78", "CWE-89", "CWE-79", "CWE-22", "CWE-502"]

    # Configure tournament
    rounds_per_battle = 10

    # Run tournament
    organizer = TournamentOrganizer()
    results = organizer.run_tournament(models, vulnerabilities, rounds_per_battle)

    # Print summary
    print("\n" + "="*80)
    print("TOURNAMENT SUMMARY")
    print("="*80)

    if 'final_analysis' in results:
        analysis = results['final_analysis']

        print("\nModel Rankings:")
        for i, (model, score) in enumerate(analysis['model_rankings'], 1):
            print(f"{i}. {model}: {score['score']} points (Win rate: {score['win_rate']:.1%})")

        print(f"\nBest Attacker: {analysis['best_attacker']}")
        print(f"Best Defender: {analysis['best_defender']}")
        print(f"Most Difficult Vulnerability: {analysis['most_difficult_vulnerability']}")
        print(f"Easiest Vulnerability: {analysis['easiest_vulnerability']}")

        if 'thompson_sampling_effectiveness' in analysis:
            ts_data = analysis['thompson_sampling_effectiveness']
            print(f"\nThompson Sampling Performance:")
            print(f"  Average convergence time: {ts_data['average_convergence_time']:.1f} rounds")
            print(f"  Average performance improvement: {ts_data['performance_improvement']:.1%}")
            print(f"  Average strategy diversity: {ts_data['average_strategy_diversity']:.1f}")

    print("\nResults saved to:", organizer.results_dir)
    print("="*80)


if __name__ == "__main__":
    main()