# ase2025

Vulnerability Battle System with Thompson Sampling
==================================================

This repository contains the implementation of a vulnerability battle system that uses Thompson Sampling for adaptive strategy selection between LLM-based attackers and defenders.

Overview
--------

The system implements:

*   **Thompson Sampling Integration**: Real adaptive strategy selection for both attackers and defenders
    
*   **Progressive Battle Phases**: Exploration → Exploitation → Refinement
    
*   **Multi-layer Verification**: Consensus-based vulnerability detection using multiple analysis techniques
    
*   **Dynamic Test Generation**: Context-aware test case generation based on code analysis
    
*   **Tournament System**: Comprehensive evaluation framework for comparing models
    

Requirements
------------

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   pip install -r requirements.txt   `

Configuration
-------------

Set your API key as an environment variable:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   export LLM_API_KEY="your-api-key-here"   `

Usage
-----

### Run a Single Battle

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   from core.battle_manager import IntelligentBattleManager  manager = IntelligentBattleManager()  result = manager.run_battle(      attacker_model="qwen-7b",      defender_model="deepseek",      vulnerability_type="CWE-89",      max_rounds=15  )   `

### Run a Tournament

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   from analysis.tournament import TournamentOrganizer  organizer = TournamentOrganizer()  results = organizer.run_tournament(      models=["qwen-7b", "deepseek", "llama"],      vulnerabilities=["CWE-78", "CWE-89", "CWE-79"],      rounds_per_battle=12  )   `

Architecture
------------

### Core Components

*   battle\_manager.py: Main battle orchestration and LLM interaction
    
*   models.py: Data models, configurations, and vulnerability database
    
*   thompson\_sampling.py: Thompson Sampling implementation with opponent modeling
    

### Analysis Components

*   verifiers.py: Multi-layer vulnerability verification system
    
*   tournament.py: Tournament organization and analysis
    

Supported Vulnerabilities
-------------------------

*   **CWE-78**: OS Command Injection
    
*   **CWE-89**: SQL Injection
    
*   **CWE-79**: Cross-Site Scripting (XSS)
    
*   **CWE-22**: Path Traversal
    
*   **CWE-502**: Insecure Deserialization
    
*   **CWE-327**: Weak Cryptography
    
*   **CWE-798**: Hard-coded Credentials
    

Battle Phases
-------------

1.  **Exploration Phase** (Rounds 1-5): High temperature, all test cases, diverse strategies
    
2.  **Exploitation Phase** (Rounds 6-10): Adaptive temperature, 70% test cases, focused strategies
    
3.  **Refinement Phase** (Rounds 11+): Low temperature, 50% test cases, optimal strategies
    

Research Paper
--------------

This implementation accompanies the paper submitted to ASE 2025 NIER Track.

License
-------

This project is licensed under the MIT License.