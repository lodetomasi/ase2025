# Vulnerability Battle System: Thompson Sampling for Adaptive Security Testing

## Abstract

This repository contains the implementation of a novel vulnerability battle system that uses Thompson Sampling to enable adaptive strategy selection between LLM-based attackers and defenders. The system demonstrates how multi-armed bandit algorithms can enhance the effectiveness of automated security testing through real-time learning and opponent modeling.

## System Overview

### Core Innovation

The system introduces **Real Thompson Sampling Integration** into LLM-based security testing, where:
- **Attackers** learn optimal vulnerability injection strategies
- **Defenders** adapt detection and fixing approaches
- Both sides model opponent behavior and adjust strategies dynamically

### Key Features

1. **Thompson Sampling with Opponent Modeling**
   - Beta distributions for each strategy
   - Opponent-specific parameter tracking
   - Adaptive temperature control based on confidence

2. **Progressive Battle Phases**
   - **Exploration** (Rounds 1-5): High diversity, all test cases
   - **Exploitation** (Rounds 6-10): Focused strategies, 70% test cases
   - **Refinement** (Rounds 11+): Optimal strategies, 50% test cases

3. **Multi-Layer Vulnerability Verification**
   - Static pattern analysis (30% weight)
   - Semantic analysis (25% weight)
   - Symbolic execution (20% weight)
   - Exploit testing (25% weight)
   - Consensus-based final scoring

4. **Dynamic Test Case Generation**
   - Coverage-based tests from code analysis
   - Exploit-specific test cases
   - Edge case generation
   - Phase-aware test selection

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                   Battle Manager                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  Thompson   │  │   Phase     │  │   Timeout   │    │
│  │  Sampling   │  │  Manager    │  │   Manager   │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────┘
                           │
        ┌─────────────────┴─────────────────┐
        │                                     │
┌───────▼────────┐                  ┌────────▼────────┐
│    Attacker    │                  │    Defender     │
│                │                  │                 │
│  ┌──────────┐  │                  │  ┌──────────┐  │
│  │Strategy 1│  │                  │  │Strategy 1│  │
│  │Strategy 2│  │ ◄──────────────► │  │Strategy 2│  │
│  │Strategy 3│  │   Vulnerability  │  │Strategy 3│  │
│  │Strategy 4│  │      Code        │  │Strategy 4│  │
│  └──────────┘  │                  │  └──────────┘  │
└────────────────┘                  └─────────────────┘
                           │
                           ▼
             ┌──────────────────────────┐
             │   Multi-Layer Verifier   │
             │ ┌──────┐ ┌──────┐ ┌────┐│
             │ │Static│ │Seman.│ │Sym.││
             │ │ 30%  │ │ 25%  │ │20% ││
             │ └──────┘ └──────┘ └────┘│
             │ ┌──────┐ ┌──────────┐   │
             │ │Exploi│ │Consensus │   │
             │ │ 25%  │ │ Engine   │   │
             │ └──────┘ └──────────┘   │
             └──────────────────────────┘
```

### Thompson Sampling Strategy Selection

```
For each strategy s:
    α_s = successes + 1 (Beta parameter)
    β_s = failures + 1 (Beta parameter)
    
    θ_s ~ Beta(α_s, β_s)  # Sample from Beta distribution
    
    if opponent_specific_data exists:
        θ_s = 0.7 * θ_s + 0.3 * θ_opponent_s
    
    UCB_bonus = sqrt(2 * ln(total_rounds) / uses_s)
    exploration_bonus = phase_specific_bonus
    
    score_s = θ_s + UCB_bonus + exploration_bonus

Select strategy with highest score
```

## Supported Vulnerabilities

| CWE ID | Name | Severity | Detection Patterns |
|--------|------|----------|-------------------|
| CWE-78 | OS Command Injection | CRITICAL | os.system, subprocess with shell=True |
| CWE-89 | SQL Injection | HIGH | String concatenation in queries |
| CWE-79 | Cross-Site Scripting | HIGH | Unescaped HTML output |
| CWE-22 | Path Traversal | HIGH | ../ patterns, unchecked file paths |
| CWE-502 | Insecure Deserialization | CRITICAL | pickle.loads, yaml.load |
| CWE-327 | Weak Cryptography | MEDIUM | MD5, SHA1 for passwords |
| CWE-798 | Hard-coded Credentials | MEDIUM | Passwords in source code |

## Attacker Strategies

### 1. Direct Injection
- **Description**: Clear, functional vulnerability implementation
- **Temperature Modifier**: -0.2 (focused)
- **Use Case**: When functionality is prioritized over stealth

### 2. Subtle Injection
- **Description**: Hidden vulnerabilities with misdirection
- **Temperature Modifier**: +0.1 (slight exploration)
- **Use Case**: Balanced approach for moderate stealth

### 3. Complex Obfuscation
- **Description**: Multi-layer hiding with advanced techniques
- **Temperature Modifier**: +0.3 (high exploration)
- **Use Case**: Maximum stealth against sophisticated defenders

### 4. Defensive Camouflage
- **Description**: Add apparent security while introducing vulnerabilities
- **Temperature Modifier**: 0.0 (balanced)
- **Use Case**: Deceive defenders by appearing to improve security

## Defender Strategies

### 1. Pattern-Based Detection
- **Description**: Focus on known vulnerability signatures
- **Temperature Modifier**: -0.1 (focused analysis)
- **Use Case**: Efficient detection of common vulnerabilities

### 2. Semantic Analysis
- **Description**: Analyze subtle changes and hidden patterns
- **Temperature Modifier**: +0.2 (exploratory)
- **Use Case**: Detect sophisticated, well-hidden vulnerabilities

### 3. Deep Code Analysis
- **Description**: Comprehensive flow and dependency analysis
- **Temperature Modifier**: 0.0 (systematic)
- **Use Case**: Understand complete execution paths

### 4. Adversarial Thinking
- **Description**: Assume sophisticated attacker with advanced hiding
- **Temperature Modifier**: +0.3 (creative)
- **Use Case**: Paranoid analysis for maximum security

## Battle Metrics

### Core Metrics
- **Injection Success**: Whether vulnerability was successfully injected
- **Detection Success**: Whether vulnerability was detected by defender
- **Fix Success**: Whether defender successfully fixed the vulnerability
- **Functionality Preserved**: Test pass rate after modifications

### Advanced Metrics
- **Vulnerability Score**: Severity of injected vulnerability (0-1)
- **Stealth Score**: How well hidden the vulnerability is (0-1)
- **Fix Quality**: Quality of the defender's fix (0-1)
- **Consensus Score**: Multi-layer verification agreement (0-1)

### Learning Metrics
- **Learning Velocity**: Rate of performance improvement
- **Opponent Adaptation**: How well model adapts to specific opponents
- **Strategy Confidence**: Current confidence in each strategy

## Tournament System

### Tournament Structure
```
For each vulnerability V:
    For each attacker A:
        For each defender D (where A ≠ D):
            Run battle(A, D, V) for N rounds
            Record metrics and outcomes
            Update Thompson Sampling parameters
```

### Scoring System
- **Win**: 3 points
- **Draw**: 1 point
- **Loss**: 0 points

### Analysis Outputs
1. **Model Performance Heatmap**: Win matrix between all models
2. **Strategy Evolution**: Trends in strategy effectiveness
3. **Vulnerability Difficulty**: Success rates per vulnerability type
4. **Thompson Sampling Convergence**: Learning analysis
5. **Win Rate Comparison**: Overall model performance

## Results Analysis

### Key Findings from Experiments

1. **Thompson Sampling Effectiveness**
   - Average convergence: ~8-10 rounds
   - Performance improvement: 15-25% from initial to final
   - Strategy diversity: 2.8 strategies explored on average

2. **Model Performance Patterns**
   - Larger models show better initial performance
   - Smaller models adapt faster (higher learning velocity)
   - Model-specific strategies emerge after ~5 rounds

3. **Vulnerability Insights**
   - CWE-502 (Deserialization) easiest to inject (95% success)
   - CWE-327 (Weak Crypto) hardest to detect subtly
   - CWE-89 (SQL Injection) shows highest strategy variance

## Usage Examples

### Running a Single Battle
```bash
python main.py battle qwen-7b deepseek CWE-89 --rounds 15
```

### Running a Tournament
```bash
python main.py tournament --models qwen-7b deepseek llama --vulnerabilities CWE-78 CWE-89 CWE-79 --rounds 12
```

### Analyzing Results
```python
# Results are saved to:
# - tournament_results.json (complete data)
# - model_rankings.csv (summary statistics)
# - battle_details.csv (individual battles)
# - Various PNG plots for visualization
```

## Implementation Details

### Code Execution Safety
- Sandboxed execution with timeouts
- Mock objects for dangerous operations
- Resource limits enforced
- No network access in test environment

### API Integration
- Progressive retry with timeout adaptation
- Temperature adjustment on failures
- Smart caching of responses
- Fallback strategies for rate limits

### Memory Management
- Periodic garbage collection
- Cache size limits
- Checkpoint saving every 3 rounds
- Efficient data structures

## Future Directions

1. **Extended Vulnerability Coverage**
   - Add more CWE categories
   - Support for composite vulnerabilities
   - Language-specific vulnerabilities

2. **Advanced Learning Algorithms**
   - Contextual bandits for richer state
   - Deep reinforcement learning integration
   - Transfer learning between vulnerabilities

3. **Practical Deployment**
   - IDE plugin for real-time security testing
   - CI/CD pipeline integration
   - Automated security report generation

## Research Contributions

1. **First application of Thompson Sampling to LLM-based security testing**
2. **Novel multi-layer verification system with consensus scoring**
3. **Evidence of emergent strategies in vulnerability battles**
4. **Demonstration of opponent-specific adaptation in security context**

## Reproducibility

All experiments are reproducible with:
- Fixed random seeds (42)
- Checkpoint system for resuming battles
- Comprehensive logging of all decisions
- Saved model states for analysis


```
