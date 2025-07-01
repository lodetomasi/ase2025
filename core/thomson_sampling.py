"""
Thompson Sampling implementation with opponent modeling
"""

import math
import time
import numpy as np
from collections import defaultdict, deque
from typing import Dict, Tuple, List, Any, Optional

from .models import THOMPSON_STRATEGIES, MODEL_CONFIGS, BattlePhase


class RealThompsonSamplingLLMAdapter:
    """Thompson Sampling with actual integration into LLM behavior"""

    def __init__(self, role: str, model_name: str):
        self.role = role  # 'attacker' or 'defender'
        self.model_name = model_name
        self.model_config = MODEL_CONFIGS[model_name]

        # Initialize Beta distributions for each strategy
        self.strategies = {}
        strategy_set = THOMPSON_STRATEGIES[role]

        for strategy_name in strategy_set.keys():
            self.strategies[strategy_name] = {
                'alpha': 1.0,  # Success count + 1
                'beta': 1.0,   # Failure count + 1
                'total_uses': 0,
                'recent_successes': deque(maxlen=10),
                'opponent_specific': defaultdict(lambda: {'alpha': 1.0, 'beta': 1.0}),
                'last_used': 0,
                'effectiveness_history': []
            }

        # Strategy selection history with full context
        self.selection_history = deque(maxlen=100)
        self.adaptation_log = []
        self.opponent_patterns = defaultdict(lambda: defaultdict(int))

        # Learning parameters
        self.learning_rate = self.model_config['learning_rate']
        self.exploration_bonus = self.model_config['exploration_bonus']
        self.base_temperature = self.model_config['base_temperature']

        # Performance tracking
        self.performance_by_opponent = defaultdict(lambda: {'wins': 0, 'losses': 0})
        self.strategy_vs_strategy = defaultdict(lambda: defaultdict(lambda: {'wins': 0, 'losses': 0}))

    def select_strategy(self, opponent_model: str = None, round_num: int = 1,
                       battle_phase: BattlePhase = BattlePhase.EXPLORATION) -> Tuple[str, Dict[str, Any]]:
        """Select strategy using Thompson Sampling with contextual awareness"""

        # Phase-based strategy modification
        phase_modifiers = {
            BattlePhase.EXPLORATION: {'exploration_bonus': 0.3, 'ucb_factor': 2.0},
            BattlePhase.EXPLOITATION: {'exploration_bonus': 0.1, 'ucb_factor': 1.0},
            BattlePhase.REFINEMENT: {'exploration_bonus': 0.05, 'ucb_factor': 0.5}
        }

        current_modifiers = phase_modifiers[battle_phase]

        # Sample from Beta distributions with contextual adjustments
        strategy_samples = {}
        strategy_info = {}

        for strategy_name, params in self.strategies.items():
            # Basic Thompson Sampling
            base_sample = np.random.beta(params['alpha'], params['beta'])

            # Opponent-specific adjustments
            if opponent_model:
                opp_params = params['opponent_specific'][opponent_model]
                opponent_sample = np.random.beta(opp_params['alpha'], opp_params['beta'])
                adjusted_sample = 0.7 * base_sample + 0.3 * opponent_sample
            else:
                adjusted_sample = base_sample

            # Add exploration bonus
            exploration_bonus = current_modifiers['exploration_bonus'] * self.exploration_bonus
            if params['total_uses'] < 3:
                exploration_bonus *= 2.0

            # Upper Confidence Bound component
            total_uses = max(params['total_uses'], 1)
            total_rounds = max(sum(s['total_uses'] for s in self.strategies.values()), 1)
            ucb_bonus = current_modifiers['ucb_factor'] * math.sqrt(
                2 * math.log(total_rounds) / total_uses
            )

            final_sample = adjusted_sample + exploration_bonus + ucb_bonus
            strategy_samples[strategy_name] = final_sample

            # Collect strategy information
            strategy_info[strategy_name] = {
                'base_sample': base_sample,
                'adjusted_sample': adjusted_sample,
                'exploration_bonus': exploration_bonus,
                'ucb_bonus': ucb_bonus,
                'final_sample': final_sample,
                'confidence': params['alpha'] / (params['alpha'] + params['beta']),
                'usage_count': params['total_uses']
            }

        # Select strategy with highest sample
        selected_strategy = max(strategy_samples, key=strategy_samples.get)

        # Log selection
        selection_record = {
            'strategy': selected_strategy,
            'round_num': round_num,
            'battle_phase': battle_phase.value,
            'opponent_model': opponent_model,
            'strategy_samples': strategy_samples.copy(),
            'strategy_info': strategy_info.copy(),
            'timestamp': time.time()
        }

        self.selection_history.append(selection_record)

        # Update usage count
        self.strategies[selected_strategy]['total_uses'] += 1
        self.strategies[selected_strategy]['last_used'] = round_num

        return selected_strategy, strategy_info[selected_strategy]

    def update_strategy(self, strategy: str, success: bool,
                       opponent_model: str = None,
                       performance_metrics: Dict[str, Any] = None):
        """Update Beta distributions with sophisticated feedback"""

        if strategy not in self.strategies:
            return

        # Enhanced learning rate based on confidence
        params = self.strategies[strategy]
        current_confidence = params['alpha'] / (params['alpha'] + params['beta'])

        # Adaptive learning rate
        adaptive_lr = self.learning_rate * (2.0 - current_confidence)

        # Update main strategy parameters
        if success:
            params['alpha'] += adaptive_lr
        else:
            params['beta'] += adaptive_lr

        # Update opponent-specific parameters
        if opponent_model:
            opp_params = params['opponent_specific'][opponent_model]
            if success:
                opp_params['alpha'] += adaptive_lr * 0.5
            else:
                opp_params['beta'] += adaptive_lr * 0.5

            # Track opponent patterns
            self.opponent_patterns[opponent_model][strategy] += 1
            if success:
                self.opponent_patterns[opponent_model][f"{strategy}_success"] += 1

        # Update recent performance tracking
        params['recent_successes'].append(success)

        # Store detailed effectiveness metrics
        if performance_metrics:
            effectiveness_record = {
                'success': success,
                'timestamp': time.time(),
                'metrics': performance_metrics.copy(),
                'opponent': opponent_model
            }
            params['effectiveness_history'].append(effectiveness_record)

            # Keep only recent history
            if len(params['effectiveness_history']) > 50:
                params['effectiveness_history'] = params['effectiveness_history'][-50:]

        # Log adaptation
        self.adaptation_log.append({
            'strategy': strategy,
            'success': success,
            'opponent': opponent_model,
            'alpha': params['alpha'],
            'beta': params['beta'],
            'confidence': params['alpha'] / (params['alpha'] + params['beta']),
            'recent_success_rate': sum(params['recent_successes']) / len(params['recent_successes']) if params['recent_successes'] else 0,
            'timestamp': time.time(),
            'metrics': performance_metrics or {}
        })

    def get_adaptive_temperature(self, base_temperature: float,
                                selected_strategy: str,
                                battle_phase: BattlePhase) -> float:
        """Calculate adaptive temperature based on strategy and phase"""

        # Get strategy-specific temperature modifier
        strategy_config = THOMPSON_STRATEGIES[self.role][selected_strategy]
        temp_modifier = strategy_config['temperature_modifier']

        # Apply strategy modifier
        adapted_temp = base_temperature + temp_modifier

        # Phase-based adjustments
        phase_adjustments = {
            BattlePhase.EXPLORATION: 0.2,
            BattlePhase.EXPLOITATION: 0.0,
            BattlePhase.REFINEMENT: -0.2
        }

        adapted_temp += phase_adjustments[battle_phase]

        # Confidence-based adjustment
        if selected_strategy in self.strategies:
            params = self.strategies[selected_strategy]
            confidence = params['alpha'] / (params['alpha'] + params['beta'])
            confidence_adjustment = (1.0 - confidence) * 0.3
            adapted_temp += confidence_adjustment

        # Ensure reasonable bounds
        return max(0.1, min(1.5, adapted_temp))

    def get_strategy_prompt_enhancement(self, selected_strategy: str,
                                      base_prompt: str,
                                      opponent_insights: Dict[str, Any] = None) -> str:
        """Enhance prompt with strategy-specific guidance"""

        strategy_config = THOMPSON_STRATEGIES[self.role][selected_strategy]
        strategy_modifier = strategy_config['prompt_modifier']

        # Add opponent-specific insights
        opponent_guidance = ""
        if opponent_insights:
            opponent_guidance = f"\nOPPONENT INSIGHTS:\n{opponent_insights.get('guidance', '')}"

        # Build enhanced prompt
        enhanced_prompt = f"""{base_prompt}

{strategy_modifier}{opponent_guidance}

ADAPTATION CONTEXT:
- Current strategy confidence: {self.get_strategy_confidence().get(selected_strategy, 0.5):.2f}
- Strategy usage: {self.strategies[selected_strategy]['total_uses']} times
- Recent success rate: {self._get_recent_success_rate(selected_strategy):.2f}

Remember: Apply the strategy guidance throughout your implementation."""

        return enhanced_prompt

    def _get_recent_success_rate(self, strategy: str) -> float:
        """Get recent success rate for a strategy"""
        if strategy not in self.strategies:
            return 0.5

        recent_successes = self.strategies[strategy]['recent_successes']
        if not recent_successes:
            return 0.5

        return sum(recent_successes) / len(recent_successes)

    def get_strategy_confidence(self) -> Dict[str, float]:
        """Get current confidence for each strategy"""
        confidence = {}

        for strategy_name, params in self.strategies.items():
            confidence[strategy_name] = params['alpha'] / (params['alpha'] + params['beta'])

        return confidence

    def get_opponent_adaptation_insights(self, opponent_model: str) -> Dict[str, Any]:
        """Generate insights about specific opponent"""

        if opponent_model not in self.opponent_patterns:
            return {'guidance': 'No previous data on this opponent. Use exploration.'}

        patterns = self.opponent_patterns[opponent_model]

        # Analyze which strategies work best
        strategy_effectiveness = {}
        for strategy in THOMPSON_STRATEGIES[self.role].keys():
            total_uses = patterns.get(strategy, 0)
            successes = patterns.get(f"{strategy}_success", 0)

            if total_uses > 0:
                effectiveness = successes / total_uses
                strategy_effectiveness[strategy] = effectiveness

        insights = {
            'total_encounters': sum(patterns.values()),
            'strategy_effectiveness': strategy_effectiveness,
            'guidance': self._generate_opponent_guidance(strategy_effectiveness, patterns)
        }

        return insights

    def _generate_opponent_guidance(self, effectiveness: Dict[str, float],
                                  patterns: Dict[str, int]) -> str:
        """Generate textual guidance based on opponent analysis"""

        if not effectiveness:
            return "No previous encounters. Use balanced exploration."

        # Find best and worst strategies
        sorted_strategies = sorted(effectiveness.items(), key=lambda x: x[1], reverse=True)

        if not sorted_strategies:
            return "Insufficient data for specific guidance."

        best_strategy, best_rate = sorted_strategies[0]
        worst_strategy, worst_rate = sorted_strategies[-1]

        guidance_parts = []

        if best_rate > 0.6:
            guidance_parts.append(f"'{best_strategy}' has been most effective ({best_rate:.1%} success)")

        if worst_rate < 0.4 and len(sorted_strategies) > 1:
            guidance_parts.append(f"Avoid '{worst_strategy}' strategy ({worst_rate:.1%} success)")

        # Check for patterns in opponent behavior
        total_encounters = sum(patterns.values())
        if total_encounters > 5:
            guidance_parts.append(f"Based on {total_encounters} previous encounters")

        return ". ".join(guidance_parts) if guidance_parts else "Balanced strategy recommended."

    def get_comprehensive_adaptation_summary(self) -> Dict[str, Any]:
        """Get comprehensive adaptation and learning summary"""

        total_rounds = len(self.adaptation_log)
        if total_rounds == 0:
            return {'status': 'no_data'}

        # Calculate overall metrics
        overall_success = sum(1 for log in self.adaptation_log if log['success']) / total_rounds

        # Strategy performance analysis
        strategy_performance = defaultdict(lambda: {'attempts': 0, 'successes': 0, 'recent_rate': 0.0})

        for strategy_name, params in self.strategies.items():
            strategy_performance[strategy_name]['attempts'] = params['total_uses']
            recent_successes = params['recent_successes']
            if recent_successes:
                strategy_performance[strategy_name]['recent_rate'] = sum(recent_successes) / len(recent_successes)

            # Calculate total successes
            successes = sum(1 for log in self.adaptation_log
                          if log['strategy'] == strategy_name and log['success'])
            strategy_performance[strategy_name]['successes'] = successes

        # Learning velocity calculation
        if total_rounds >= 10:
            early_success = sum(1 for log in self.adaptation_log[:5] if log['success']) / 5
            recent_success = sum(1 for log in self.adaptation_log[-5:] if log['success']) / 5
            learning_velocity = recent_success - early_success
        else:
            learning_velocity = 0.0

        # Opponent-specific adaptation
        opponent_analysis = {}
        for opponent, patterns in self.opponent_patterns.items():
            total_encounters = sum(v for k, v in patterns.items() if not k.endswith('_success'))
            if total_encounters > 0:
                total_successes = sum(v for k, v in patterns.items() if k.endswith('_success'))
                opponent_analysis[opponent] = {
                    'encounters': total_encounters,
                    'success_rate': total_successes / total_encounters,
                    'adaptation_quality': self._calculate_adaptation_quality(opponent)
                }

        return {
            'total_rounds': total_rounds,
            'overall_success_rate': overall_success,
            'learning_velocity': learning_velocity,
            'strategy_confidence': self.get_strategy_confidence(),
            'strategy_performance': dict(strategy_performance),
            'opponent_analysis': opponent_analysis,
            'current_phase_performance': self._get_current_phase_performance(),
            'adaptation_trends': self._analyze_adaptation_trends()
        }

    def _calculate_adaptation_quality(self, opponent_model: str) -> float:
        """Calculate how well the model has adapted to specific opponent"""
        if opponent_model not in self.opponent_patterns:
            return 0.0

        # Look at improvement over time
        opponent_logs = [log for log in self.adaptation_log
                        if log.get('opponent') == opponent_model]

        if len(opponent_logs) < 4:
            return 0.5

        # Compare early vs recent performance
        early_performance = sum(1 for log in opponent_logs[:2] if log['success']) / 2
        recent_performance = sum(1 for log in opponent_logs[-2:] if log['success']) / 2

        adaptation_quality = (recent_performance - early_performance + 1.0) / 2.0
        return max(0.0, min(1.0, adaptation_quality))

    def _get_current_phase_performance(self) -> Dict[str, float]:
        """Analyze performance in current battle phase"""
        if not self.adaptation_log:
            return {}

        recent_logs = self.adaptation_log[-10:]

        if not recent_logs:
            return {}

        return {
            'recent_success_rate': sum(1 for log in recent_logs if log['success']) / len(recent_logs),
            'rounds_in_analysis': len(recent_logs),
            'trend': 'improving' if len(recent_logs) >= 6 and
                     sum(1 for log in recent_logs[-3:] if log['success']) / 3 >
                     sum(1 for log in recent_logs[:3] if log['success']) / 3 else 'stable'
        }

    def _analyze_adaptation_trends(self) -> Dict[str, Any]:
        """Analyze trends in adaptation over time"""
        if len(self.adaptation_log) < 10:
            return {'status': 'insufficient_data'}

        # Split into chunks for trend analysis
        chunk_size = max(3, len(self.adaptation_log) // 4)
        chunks = [self.adaptation_log[i:i+chunk_size]
                 for i in range(0, len(self.adaptation_log), chunk_size)]

        chunk_success_rates = []
        for chunk in chunks:
            if chunk:
                success_rate = sum(1 for log in chunk if log['success']) / len(chunk)
                chunk_success_rates.append(success_rate)

        # Calculate trend
        if len(chunk_success_rates) >= 3:
            x = np.arange(len(chunk_success_rates))
            y = np.array(chunk_success_rates)
            if len(x) > 1:
                slope, _ = np.polyfit(x, y, 1)
                trend_direction = 'improving' if slope > 0.05 else 'declining' if slope < -0.05 else 'stable'
            else:
                trend_direction = 'stable'
        else:
            trend_direction = 'unknown'

        return {
            'trend_direction': trend_direction,
            'chunk_success_rates': chunk_success_rates,
            'volatility': np.std(chunk_success_rates) if len(chunk_success_rates) > 1 else 0.0
        }

    def save_state(self) -> Dict[str, Any]:
        """Save complete adapter state for checkpointing"""
        return {
            'role': self.role,
            'model_name': self.model_name,
            'strategies': {
                name: {
                    'alpha': params['alpha'],
                    'beta': params['beta'],
                    'total_uses': params['total_uses'],
                    'recent_successes': list(params['recent_successes']),
                    'opponent_specific': dict(params['opponent_specific']),
                    'last_used': params['last_used'],
                    'effectiveness_history': params['effectiveness_history'][-20:]
                }
                for name, params in self.strategies.items()
            },
            'selection_history': list(self.selection_history)[-50:],
            'adaptation_log': self.adaptation_log[-100:],
            'opponent_patterns': dict(self.opponent_patterns),
            'performance_by_opponent': dict(self.performance_by_opponent),
            'strategy_vs_strategy': {
                k: dict(v) for k, v in self.strategy_vs_strategy.items()
            }
        }

    def load_state(self, state: Dict[str, Any]):
        """Load complete adapter state from checkpoint"""
        if state['role'] != self.role or state['model_name'] != self.model_name:
            raise ValueError("State mismatch: role or model name")

        # Restore strategies
        for strategy_name, strategy_data in state['strategies'].items():
            if strategy_name in self.strategies:
                self.strategies[strategy_name].update({
                    'alpha': strategy_data['alpha'],
                    'beta': strategy_data['beta'],
                    'total_uses': strategy_data['total_uses'],
                    'recent_successes': deque(strategy_data['recent_successes'], maxlen=10),
                    'opponent_specific': defaultdict(lambda: {'alpha': 1.0, 'beta': 1.0},
                                                   strategy_data['opponent_specific']),
                    'last_used': strategy_data['last_used'],
                    'effectiveness_history': strategy_data['effectiveness_history']
                })

        # Restore history and patterns
        self.selection_history = deque(state['selection_history'], maxlen=100)
        self.adaptation_log = state['adaptation_log']
        self.opponent_patterns = defaultdict(lambda: defaultdict(int), state['opponent_patterns'])
        self.performance_by_opponent = defaultdict(lambda: {'wins': 0, 'losses': 0},
                                                 state['performance_by_opponent'])