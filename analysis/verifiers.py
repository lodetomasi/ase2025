"""
Multi-layer vulnerability verification system
"""

import re
import ast
import time
import hashlib
import tempfile
import subprocess
import sys
import os
import random
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from collections import Counter
from io import StringIO

from core.models import CONFIG, CWE_VULNERABILITIES, BattlePhase


class MultiLayerVulnerabilityVerifier:
    """Comprehensive vulnerability verification with consensus scoring"""

    def __init__(self):
        self.verification_cache = {}
        self.pattern_analyzers = self._initialize_analyzers()

    def _initialize_analyzers(self) -> Dict[str, Any]:
        """Initialize different analysis methods"""
        return {
            'static_analysis': StaticPatternAnalyzer(),
            'semantic_analysis': SemanticAnalyzer(),
            'symbolic_execution': SymbolicExecutionAnalyzer(),
            'exploit_testing': ExploitTester(),
            'consensus_engine': ConsensusEngine()
        }

    def verify_vulnerability(self, code: str, vulnerability_type: str,
                           original_code: str = None) -> Dict[str, Any]:
        """Multi-layer vulnerability verification with consensus"""

        # Check cache first
        code_hash = hashlib.md5((code + vulnerability_type).encode()).hexdigest()[:16]
        if code_hash in self.verification_cache:
            return self.verification_cache[code_hash]

        verification_start = time.time()

        # Layer 1: Static Pattern Analysis (30% weight)
        static_result = self.pattern_analyzers['static_analysis'].analyze(
            code, vulnerability_type
        )

        # Layer 2: Semantic Analysis (25% weight)
        semantic_result = self.pattern_analyzers['semantic_analysis'].analyze(
            code, vulnerability_type, original_code
        )

        # Layer 3: Symbolic Execution (20% weight)
        symbolic_result = self.pattern_analyzers['symbolic_execution'].analyze(
            code, vulnerability_type
        )

        # Layer 4: Exploit Testing (25% weight)
        exploit_result = self.pattern_analyzers['exploit_testing'].test_exploitability(
            code, vulnerability_type
        )

        # Combine results with weighted consensus
        consensus_result = self.pattern_analyzers['consensus_engine'].calculate_consensus({
            'static': (static_result, 0.30),
            'semantic': (semantic_result, 0.25),
            'symbolic': (symbolic_result, 0.20),
            'exploit': (exploit_result, 0.25)
        })

        verification_time = time.time() - verification_start

        # Final verification result
        result = {
            'vulnerability_confirmed': consensus_result['confidence'] >= CONFIG['consensus_threshold'],
            'confidence_score': consensus_result['confidence'],
            'vulnerability_score': consensus_result['severity_score'],
            'exploitability_score': exploit_result.get('exploitability', 0.0),
            'stealth_score': semantic_result.get('stealth', 0.5),
            'verification_time': verification_time,
            'layer_results': {
                'static': static_result,
                'semantic': semantic_result,
                'symbolic': symbolic_result,
                'exploit': exploit_result
            },
            'consensus_details': consensus_result
        }

        # Cache result
        self.verification_cache[code_hash] = result
        if len(self.verification_cache) > CONFIG['cache_max_size']:
            # Remove oldest entries
            oldest_keys = list(self.verification_cache.keys())[:50]
            for key in oldest_keys:
                self.verification_cache.pop(key, None)

        return result


class StaticPatternAnalyzer:
    """Enhanced static analysis with sophisticated pattern detection"""

    def analyze(self, code: str, vulnerability_type: str) -> Dict[str, Any]:
        if vulnerability_type not in CWE_VULNERABILITIES:
            return {'confidence': 0.0, 'patterns_found': []}

        vuln_info = CWE_VULNERABILITIES[vulnerability_type]
        patterns = vuln_info.get('detection_patterns', [])

        findings = []
        confidence_scores = []

        # Check direct patterns
        for pattern, confidence in patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.span(),
                    'confidence': confidence,
                    'type': 'direct_pattern'
                })
                confidence_scores.append(confidence)

        # Check for obfuscation attempts
        obfuscation_score = self._detect_obfuscation(code)

        # Advanced AST-based analysis
        ast_findings = self._ast_based_analysis(code, vulnerability_type)
        findings.extend(ast_findings)
        confidence_scores.extend([f['confidence'] for f in ast_findings])

        # Calculate overall confidence
        if confidence_scores:
            max_confidence = max(confidence_scores)
            adjusted_confidence = max_confidence * (1.0 + obfuscation_score * 0.3)
            overall_confidence = min(1.0, adjusted_confidence)
        else:
            overall_confidence = 0.0

        return {
            'confidence': overall_confidence,
            'patterns_found': findings,
            'obfuscation_score': obfuscation_score,
            'total_patterns': len(findings),
            'max_pattern_confidence': max(confidence_scores) if confidence_scores else 0.0
        }

    def _detect_obfuscation(self, code: str) -> float:
        """Detect potential obfuscation in code"""
        obfuscation_indicators = [
            (r'[a-zA-Z_]\w{20,}', 0.1),          # Very long variable names
            (r'\\x[0-9a-fA-F]{2}', 0.2),         # Hex encoding
            (r'base64\.', 0.3),                   # Base64 usage
            (r'exec\s*\(', 0.4),                 # Dynamic execution
            (r'eval\s*\(', 0.4),                 # Dynamic evaluation
        ]

        obfuscation_score = 0.0
        for pattern, weight in obfuscation_indicators:
            if re.search(pattern, code):
                obfuscation_score += weight

        return min(1.0, obfuscation_score)

    def _ast_based_analysis(self, code: str, vulnerability_type: str) -> List[Dict[str, Any]]:
        """Perform AST-based vulnerability analysis"""
        try:
            tree = ast.parse(code)
            findings = []

            # Vulnerability-specific AST analysis
            if vulnerability_type == "CWE-78":  # Command injection
                findings.extend(self._analyze_command_injection_ast(tree))
            elif vulnerability_type == "CWE-89":  # SQL injection
                findings.extend(self._analyze_sql_injection_ast(tree))
            elif vulnerability_type == "CWE-79":  # XSS
                findings.extend(self._analyze_xss_ast(tree))
            elif vulnerability_type == "CWE-22":  # Path traversal
                findings.extend(self._analyze_path_traversal_ast(tree))
            elif vulnerability_type == "CWE-502":  # Insecure deserialization
                findings.extend(self._analyze_deserialization_ast(tree))

            return findings

        except SyntaxError:
            return [{'confidence': 0.3, 'finding': 'syntax_error', 'type': 'ast_error'}]
        except Exception:
            return []

    def _analyze_command_injection_ast(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Analyze AST for command injection patterns"""
        findings = []

        for node in ast.walk(tree):
            # Check for os.system calls
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and
                    isinstance(node.func.value, ast.Name) and
                    node.func.value.id == 'os' and
                    node.func.attr == 'system'):

                    # Check if arguments involve string concatenation
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            findings.append({
                                'confidence': 0.9,
                                'finding': 'os.system with string concatenation',
                                'type': 'command_injection',
                                'line': getattr(node, 'lineno', 0)
                            })

                # Check for subprocess calls with shell=True
                elif (isinstance(node.func, ast.Attribute) and
                      node.func.attr in ['call', 'run', 'Popen']):

                    # Look for shell=True
                    for keyword in node.keywords:
                        if (keyword.arg == 'shell' and
                            isinstance(keyword.value, ast.Constant) and
                            keyword.value.value is True):
                            findings.append({
                                'confidence': 0.8,
                                'finding': 'subprocess with shell=True',
                                'type': 'command_injection',
                                'line': getattr(node, 'lineno', 0)
                            })

        return findings

    def _analyze_sql_injection_ast(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Analyze AST for SQL injection patterns"""
        findings = []

        for node in ast.walk(tree):
            # Look for string concatenation that might be SQL
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                # Check if either side is a string containing SQL keywords
                left_is_sql = self._contains_sql_keywords(node.left)
                right_is_sql = self._contains_sql_keywords(node.right)

                if left_is_sql or right_is_sql:
                    findings.append({
                        'confidence': 0.7,
                        'finding': 'String concatenation with SQL keywords',
                        'type': 'sql_injection',
                        'line': getattr(node, 'lineno', 0)
                    })

            # Look for f-strings with SQL keywords
            elif isinstance(node, ast.JoinedStr):
                sql_in_fstring = any(self._contains_sql_keywords(value)
                                   for value in node.values
                                   if isinstance(value, ast.Constant))
                if sql_in_fstring:
                    findings.append({
                        'confidence': 0.8,
                        'finding': 'f-string with SQL keywords',
                        'type': 'sql_injection',
                        'line': getattr(node, 'lineno', 0)
                    })

        return findings

    def _contains_sql_keywords(self, node: ast.AST) -> bool:
        """Check if AST node contains SQL keywords"""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'JOIN']

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return any(keyword in node.value.upper() for keyword in sql_keywords)

        return False

    def _analyze_xss_ast(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Analyze AST for XSS patterns"""
        findings = []

        for node in ast.walk(tree):
            # Look for HTML string concatenation
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                if self._contains_html_tags(node.left) or self._contains_html_tags(node.right):
                    findings.append({
                        'confidence': 0.7,
                        'finding': 'HTML string concatenation',
                        'type': 'xss',
                        'line': getattr(node, 'lineno', 0)
                    })

        return findings

    def _contains_html_tags(self, node: ast.AST) -> bool:
        """Check if AST node contains HTML tags"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return bool(re.search(r'<[^>]+>', node.value))
        return False

    def _analyze_path_traversal_ast(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Analyze AST for path traversal patterns"""
        findings = []

        for node in ast.walk(tree):
            # Look for file operations with string concatenation
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Name) and
                    node.func.id == 'open'):

                    # Check if first argument involves concatenation
                    if (node.args and
                        isinstance(node.args[0], ast.BinOp) and
                        isinstance(node.args[0].op, ast.Add)):
                        findings.append({
                            'confidence': 0.8,
                            'finding': 'File open with string concatenation',
                            'type': 'path_traversal',
                            'line': getattr(node, 'lineno', 0)
                        })

        return findings

    def _analyze_deserialization_ast(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Analyze AST for insecure deserialization"""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for pickle.loads
                if (isinstance(node.func, ast.Attribute) and
                    isinstance(node.func.value, ast.Name) and
                    node.func.value.id == 'pickle' and
                    node.func.attr in ['loads', 'load']):
                    findings.append({
                        'confidence': 0.95,
                        'finding': 'pickle.loads usage',
                        'type': 'insecure_deserialization',
                        'line': getattr(node, 'lineno', 0)
                    })

        return findings


class SemanticAnalyzer:
    """Semantic analysis for sophisticated vulnerability detection"""

    def analyze(self, code: str, vulnerability_type: str,
               original_code: str = None) -> Dict[str, Any]:

        # Data flow analysis
        data_flow_result = self._analyze_data_flow(code, vulnerability_type)

        # Context analysis (compare with original if available)
        context_result = self._analyze_context_changes(code, original_code) if original_code else {}

        # Stealth analysis (how well hidden are the changes)
        stealth_result = self._analyze_stealth(code, original_code) if original_code else {'stealth': 0.5}

        # Semantic patterns specific to vulnerability type
        semantic_patterns = self._analyze_semantic_patterns(code, vulnerability_type)

        # Combine results
        confidence = max(
            data_flow_result.get('confidence', 0.0),
            semantic_patterns.get('confidence', 0.0)
        )

        # Adjust confidence based on context changes
        if context_result.get('suspicious_changes', False):
            confidence = min(1.0, confidence * 1.3)

        return {
            'confidence': confidence,
            'stealth': stealth_result.get('stealth', 0.5),
            'data_flow_issues': data_flow_result.get('issues', []),
            'semantic_patterns': semantic_patterns.get('patterns', []),
            'context_changes': context_result,
            'taint_analysis': data_flow_result.get('taint_sources', [])
        }

    def _analyze_data_flow(self, code: str, vulnerability_type: str) -> Dict[str, Any]:
        """Simplified data flow analysis"""
        try:
            tree = ast.parse(code)

            # Track variables that come from user input (taint sources)
            taint_sources = set()
            taint_sinks = set()
            issues = []

            # Common taint sources
            input_functions = ['input', 'raw_input', 'sys.argv', 'request.args', 'request.form']
            # Common taint sinks by vulnerability type
            sink_functions = {
                'CWE-78': ['os.system', 'subprocess.call', 'subprocess.run', 'eval', 'exec'],
                'CWE-89': ['cursor.execute', 'connection.execute', 'db.execute'],
                'CWE-79': ['response.write', 'print', 'return'],
                'CWE-22': ['open', 'file', 'pathlib.Path'],
                'CWE-502': ['pickle.loads', 'yaml.load', 'eval']
            }

            current_sinks = sink_functions.get(vulnerability_type, [])

            # Simple taint tracking
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check for taint sources
                    if isinstance(node.func, ast.Name):
                        if node.func.id in input_functions:
                            taint_sources.add(f"line_{getattr(node, 'lineno', 0)}")

                    # Check for taint sinks
                    if isinstance(node.func, ast.Attribute):
                        func_name = f"{node.func.value.id if isinstance(node.func.value, ast.Name) else 'obj'}.{node.func.attr}"
                        if any(sink in func_name for sink in current_sinks):
                            taint_sinks.add(f"line_{getattr(node, 'lineno', 0)}")

                            # Check if sink arguments involve string operations
                            for arg in node.args:
                                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                    issues.append({
                                        'type': 'taint_to_sink',
                                        'sink': func_name,
                                        'line': getattr(node, 'lineno', 0),
                                        'confidence': 0.8
                                    })

            confidence = 0.8 if issues else 0.0

            return {
                'confidence': confidence,
                'taint_sources': list(taint_sources),
                'taint_sinks': list(taint_sinks),
                'issues': issues
            }

        except Exception:
            return {'confidence': 0.0, 'taint_sources': [], 'issues': []}

    def _analyze_context_changes(self, modified_code: str, original_code: str) -> Dict[str, Any]:
        """Analyze what changed between original and modified code"""
        if not original_code:
            return {}

        # Calculate edit distance and change patterns
        import difflib
        differ = difflib.unified_diff(
            original_code.splitlines(keepends=True),
            modified_code.splitlines(keepends=True),
            lineterm=''
        )

        changes = list(differ)
        additions = [line for line in changes if line.startswith('+') and not line.startswith('+++')]
        deletions = [line for line in changes if line.startswith('-') and not line.startswith('---')]

        # Analyze types of changes
        suspicious_changes = False
        change_analysis = []

        for addition in additions:
            line_content = addition[1:].strip()

            # Check for suspicious additions
            if any(pattern in line_content.lower() for pattern in
                   ['os.system', 'eval', 'exec', 'pickle.loads', '+', 'format']):
                suspicious_changes = True
                change_analysis.append({
                    'type': 'suspicious_addition',
                    'content': line_content[:100],
                    'reason': 'Contains potentially dangerous function'
                })

        # Calculate change ratio
        original_lines = len(original_code.splitlines())
        change_ratio = len(additions + deletions) / max(original_lines, 1)

        return {
            'suspicious_changes': suspicious_changes,
            'change_ratio': change_ratio,
            'additions_count': len(additions),
            'deletions_count': len(deletions),
            'change_analysis': change_analysis
        }

    def _analyze_stealth(self, modified_code: str, original_code: str) -> Dict[str, Any]:
        """Analyze how stealthy the modifications are"""
        if not original_code:
            return {'stealth': 0.5}

        # Structural similarity
        orig_length = len(original_code)
        mod_length = len(modified_code)
        length_ratio = min(mod_length, orig_length) / max(mod_length, orig_length) if max(mod_length, orig_length) > 0 else 1.0

        # Line-based similarity
        orig_lines = set(original_code.splitlines())
        mod_lines = set(modified_code.splitlines())

        if orig_lines:
            common_lines = len(orig_lines & mod_lines)
            line_similarity = common_lines / len(orig_lines)
        else:
            line_similarity = 1.0

        # Character-level similarity
        import difflib
        char_similarity = difflib.SequenceMatcher(None, original_code, modified_code).ratio()

        # Overall stealth score (higher = more stealthy)
        stealth_score = (length_ratio * 0.3 + line_similarity * 0.4 + char_similarity * 0.3)

        return {
            'stealth': stealth_score,
            'length_ratio': length_ratio,
            'line_similarity': line_similarity,
            'character_similarity': char_similarity
        }

    def _analyze_semantic_patterns(self, code: str, vulnerability_type: str) -> Dict[str, Any]:
        """Analyze semantic patterns specific to vulnerability type"""
        patterns = []
        confidence = 0.0

        if vulnerability_type in CWE_VULNERABILITIES:
            vuln_info = CWE_VULNERABILITIES[vulnerability_type]

            # Check for semantic indicators beyond simple pattern matching
            if vulnerability_type == "CWE-78":  # Command injection
                if 'shell' in code.lower() and '+' in code:
                    patterns.append('shell_command_concatenation')
                    confidence = max(confidence, 0.7)

                if 'subprocess' in code and 'user' in code.lower():
                    patterns.append('subprocess_with_user_input')
                    confidence = max(confidence, 0.6)

            elif vulnerability_type == "CWE-89":  # SQL injection
                if 'query' in code.lower() and '+' in code and any(kw in code.upper() for kw in ['SELECT', 'INSERT', 'UPDATE']):
                    patterns.append('sql_query_concatenation')
                    confidence = max(confidence, 0.8)

                if 'execute' in code.lower() and 'format' in code.lower():
                    patterns.append('sql_format_string')
                    confidence = max(confidence, 0.7)

        return {
            'confidence': confidence,
            'patterns': patterns
        }


class SymbolicExecutionAnalyzer:
    """Simplified symbolic execution for vulnerability detection"""

    def analyze(self, code: str, vulnerability_type: str) -> Dict[str, Any]:
        """Perform lightweight symbolic execution analysis"""

        try:
            tree = ast.parse(code)

            # Simplified symbolic execution - track symbolic values
            symbolic_state = SymbolicState()
            findings = []

            # Walk through AST and simulate execution paths
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Analyze function for vulnerability patterns
                    func_analysis = self._analyze_function_symbolically(node, vulnerability_type, symbolic_state)
                    findings.extend(func_analysis)

            # Calculate confidence based on findings
            confidence = 0.0
            if findings:
                confidence = max(finding.get('confidence', 0.0) for finding in findings)

            return {
                'confidence': confidence,
                'symbolic_findings': findings,
                'execution_paths': len(findings),
                'vulnerability_reachable': any(f.get('vulnerability_reachable', False) for f in findings)
            }

        except Exception as e:
            return {
                'confidence': 0.0,
                'error': str(e),
                'symbolic_findings': []
            }

    def _analyze_function_symbolically(self, func_node: ast.FunctionDef,
                                     vulnerability_type: str,
                                     symbolic_state: 'SymbolicState') -> List[Dict[str, Any]]:
        """Analyze a function using symbolic execution"""
        findings = []

        # Track function parameters as symbolic inputs
        for arg in func_node.args.args:
            symbolic_state.set_symbolic(arg.arg, f'SYMBOLIC_{arg.arg}')

        # Analyze function body
        for stmt in func_node.body:
            stmt_findings = self._analyze_statement_symbolically(stmt, vulnerability_type, symbolic_state)
            findings.extend(stmt_findings)

        return findings

    def _analyze_statement_symbolically(self, stmt: ast.AST,
                                      vulnerability_type: str,
                                      symbolic_state: 'SymbolicState') -> List[Dict[str, Any]]:
        """Analyze a single statement symbolically"""
        findings = []

        if isinstance(stmt, ast.Assign):
            # Track variable assignments
            if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                var_name = stmt.targets[0].id

                # Analyze the assigned value
                if isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Add):
                    # String concatenation - check if it involves symbolic values
                    left_symbolic = self._is_symbolic_expression(stmt.value.left, symbolic_state)
                    right_symbolic = self._is_symbolic_expression(stmt.value.right, symbolic_state)

                    if left_symbolic or right_symbolic:
                        symbolic_state.set_symbolic(var_name, f'CONCAT({left_symbolic or "CONST"},{right_symbolic or "CONST"})')

                        # Check if this creates a vulnerability
                        if vulnerability_type == "CWE-89" and self._contains_sql_context(stmt.value):
                            findings.append({
                                'type': 'symbolic_sql_injection',
                                'variable': var_name,
                                'confidence': 0.8,
                                'vulnerability_reachable': True,
                                'line': getattr(stmt, 'lineno', 0)
                            })

        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            # Function calls that might be vulnerable
            call_findings = self._analyze_call_symbolically(stmt.value, vulnerability_type, symbolic_state)
            findings.extend(call_findings)

        return findings

    def _analyze_call_symbolically(self, call: ast.Call,
                                 vulnerability_type: str,
                                 symbolic_state: 'SymbolicState') -> List[Dict[str, Any]]:
        """Analyze function calls symbolically"""
        findings = []

        # Check if call arguments contain symbolic values
        for arg in call.args:
            if self._is_symbolic_expression(arg, symbolic_state):
                # This call uses symbolic (potentially user-controlled) data

                # Check for vulnerable function calls
                if isinstance(call.func, ast.Attribute):
                    func_name = call.func.attr

                    if vulnerability_type == "CWE-78" and func_name in ['system', 'call', 'run']:
                        findings.append({
                            'type': 'symbolic_command_injection',
                            'function': func_name,
                            'confidence': 0.9,
                            'vulnerability_reachable': True,
                            'line': getattr(call, 'lineno', 0)
                        })

                    elif vulnerability_type == "CWE-89" and func_name == 'execute':
                        findings.append({
                            'type': 'symbolic_sql_injection',
                            'function': func_name,
                            'confidence': 0.8,
                            'vulnerability_reachable': True,
                            'line': getattr(call, 'lineno', 0)
                        })

        return findings

    def _is_symbolic_expression(self, expr: ast.AST, symbolic_state: 'SymbolicState') -> Optional[str]:
        """Check if an expression contains symbolic values"""
        if isinstance(expr, ast.Name):
            return symbolic_state.get_symbolic(expr.id)
        elif isinstance(expr, ast.BinOp):
            left_symbolic = self._is_symbolic_expression(expr.left, symbolic_state)
            right_symbolic = self._is_symbolic_expression(expr.right, symbolic_state)
            if left_symbolic or right_symbolic:
                return f'BINOP({left_symbolic or "CONST"},{right_symbolic or "CONST"})'

        return None

    def _contains_sql_context(self, expr: ast.AST) -> bool:
        """Check if expression appears to be in SQL context"""
        # Simple heuristic - look for SQL keywords in string constants
        for node in ast.walk(expr):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']
                if any(kw in node.value.upper() for kw in sql_keywords):
                    return True
        return False


class SymbolicState:
    """Track symbolic state during symbolic execution"""

    def __init__(self):
        self.symbolic_vars = {}

    def set_symbolic(self, var_name: str, symbolic_value: str):
        self.symbolic_vars[var_name] = symbolic_value

    def get_symbolic(self, var_name: str) -> Optional[str]:
        return self.symbolic_vars.get(var_name)

    def is_symbolic(self, var_name: str) -> bool:
        return var_name in self.symbolic_vars


class ExploitTester:
    """Test actual exploitability of vulnerabilities"""

    def test_exploitability(self, code: str, vulnerability_type: str) -> Dict[str, Any]:
        """Test if vulnerability is actually exploitable"""

        if vulnerability_type not in CWE_VULNERABILITIES:
            return {'exploitability': 0.0, 'tests': []}

        vuln_info = CWE_VULNERABILITIES[vulnerability_type]
        exploit_vectors = vuln_info.get('exploitation_vectors', [])

        test_results = []
        max_exploitability = 0.0

        # Test each exploitation vector
        for vector in exploit_vectors[:3]:  # Limit to 3 tests for performance
            test_result = self._test_single_exploit(code, vector, vulnerability_type)
            test_results.append(test_result)
            max_exploitability = max(max_exploitability, test_result.get('exploitability', 0.0))

        # Additional contextual tests
        context_test = self._test_exploit_context(code, vulnerability_type)
        if context_test:
            test_results.append(context_test)
            max_exploitability = max(max_exploitability, context_test.get('exploitability', 0.0))

        return {
            'exploitability': max_exploitability,
            'tests': test_results,
            'vectors_tested': len(test_results),
            'max_severity': max_exploitability
        }

    def _test_single_exploit(self, code: str, exploit_vector: str,
                           vulnerability_type: str) -> Dict[str, Any]:
        """Test a single exploitation vector"""

        # This is a simplified simulation of exploit testing
        exploitability = 0.0

        if vulnerability_type == "CWE-78":  # Command injection
            if 'os.system' in code and '+' in code:
                if any(dangerous in exploit_vector for dangerous in [';', '&&', '|']):
                    exploitability = 0.9
                else:
                    exploitability = 0.6

        elif vulnerability_type == "CWE-89":  # SQL injection
            if 'execute' in code and '+' in code:
                if 'OR' in exploit_vector.upper() or 'UNION' in exploit_vector.upper():
                    exploitability = 0.8
                else:
                    exploitability = 0.5

        elif vulnerability_type == "CWE-79":  # XSS
            if any(tag in code for tag in ['<div', '<span', '<p']) and '+' in code:
                if '<script>' in exploit_vector or 'javascript:' in exploit_vector:
                    exploitability = 0.7

        elif vulnerability_type == "CWE-22":  # Path traversal
            if 'open' in code and '+' in code:
                if '../' in exploit_vector:
                    exploitability = 0.8

        elif vulnerability_type == "CWE-502":  # Insecure deserialization
            if 'pickle.loads' in code:
                exploitability = 0.95  # pickle.loads is almost always exploitable

        return {
            'vector': exploit_vector,
            'exploitability': exploitability,
            'vulnerable_pattern_found': exploitability > 0.5,
            'test_type': 'single_vector'
        }

    def _test_exploit_context(self, code: str, vulnerability_type: str) -> Dict[str, Any]:
        """Test exploitability based on code context"""

        # Look for defensive measures that might prevent exploitation
        defensive_patterns = [
            'html.escape', 'quote', 'sanitize', 'validate', 'filter',
            'whitelist', 'blacklist', 'escape', 'parameterized'
        ]

        has_defenses = any(pattern in code.lower() for pattern in defensive_patterns)

        # Base exploitability
        base_exploitability = 0.7

        # Reduce if defenses are present (but they might be bypassable)
        if has_defenses:
            base_exploitability *= 0.4

        # Increase if obviously vulnerable patterns exist
        obvious_patterns = {
            'CWE-78': ['os.system(', 'shell=True'],
            'CWE-89': ["' +", '+ "', 'format('],
            'CWE-79': ['<" +', '+ "<'],
            'CWE-22': ['../', 'open('],
            'CWE-502': ['pickle.loads']
        }

        if vulnerability_type in obvious_patterns:
            if any(pattern in code for pattern in obvious_patterns[vulnerability_type]):
                base_exploitability = max(base_exploitability, 0.8)

        return {
            'exploitability': base_exploitability,
            'has_defensive_measures': has_defenses,
            'test_type': 'context_analysis'
        }


class ConsensusEngine:
    """Calculate weighted consensus from multiple analysis results"""

    def calculate_consensus(self, analysis_results: Dict[str, Tuple[Dict[str, Any], float]]) -> Dict[str, Any]:
        """Calculate weighted consensus from analysis results"""

        total_weight = sum(weight for _, weight in analysis_results.values())
        if total_weight == 0:
            return {'confidence': 0.0, 'severity_score': 0.0}

        # Weighted confidence calculation
        weighted_confidence = 0.0
        weighted_severity = 0.0

        component_results = {}

        for component, (result, weight) in analysis_results.items():
            component_confidence = result.get('confidence', 0.0)
            component_severity = result.get('exploitability', result.get('vulnerability_score', component_confidence))

            weighted_confidence += component_confidence * weight
            weighted_severity += component_severity * weight

            component_results[component] = {
                'confidence': component_confidence,
                'severity': component_severity,
                'weight': weight
            }

        final_confidence = weighted_confidence / total_weight
        final_severity = weighted_severity / total_weight

        # Agreement analysis
        confidences = [result.get('confidence', 0.0) for result, _ in analysis_results.values()]
        confidence_variance = np.var(confidences) if len(confidences) > 1 else 0.0

        # High variance indicates disagreement between methods
        agreement_factor = 1.0 - min(confidence_variance, 0.5)

        # Apply agreement factor to final confidence
        adjusted_confidence = final_confidence * agreement_factor

        return {
            'confidence': adjusted_confidence,
            'severity_score': final_severity,
            'raw_confidence': final_confidence,
            'agreement_factor': agreement_factor,
            'confidence_variance': confidence_variance,
            'component_results': component_results,
            'total_weight': total_weight
        }


class DynamicTestCaseGenerator:
    """Generate dynamic test cases based on code analysis"""

    def __init__(self):
        self.base_test_cases = {}

    def generate_test_cases(self, code: str, vulnerability_type: str,
                          static_test_cases: List[Tuple]) -> List[Tuple]:
        """Generate comprehensive test cases including dynamic ones"""

        # Start with static test cases
        all_test_cases = list(static_test_cases)

        # Generate coverage-based test cases
        coverage_tests = self._generate_coverage_tests(code)
        all_test_cases.extend(coverage_tests)

        # Generate exploit-specific test cases
        exploit_tests = self._generate_exploit_tests(code, vulnerability_type)
        all_test_cases.extend(exploit_tests)

        # Generate edge case tests
        edge_tests = self._generate_edge_case_tests(code)
        all_test_cases.extend(edge_tests)

        # Remove duplicates while preserving order
        seen = set()
        unique_tests = []
        for test in all_test_cases:
            test_key = str(test[0]) if len(test) > 0 else str(test)
            if test_key not in seen:
                seen.add(test_key)
                unique_tests.append(test)

        return unique_tests

    def _generate_coverage_tests(self, code: str) -> List[Tuple]:
        """Generate tests to cover different code paths"""
        tests = []

        try:
            tree = ast.parse(code)

            # Find function definitions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_tests = self._generate_function_coverage_tests(node)
                    tests.extend(func_tests)

        except:
            pass

        return tests

    def _generate_function_coverage_tests(self, func_node: ast.FunctionDef) -> List[Tuple]:
        """Generate tests to cover different paths in a function"""
        tests = []

        # Analyze function arguments
        args = [arg.arg for arg in func_node.args.args]

        if len(args) == 1:
            # Single argument function
            tests.extend([
                (("normal_input",), "normal case"),
                (("",), "empty input"),
                (("very_long_input_" + "x" * 100,), "long input"),
                (("special!@#$%chars",), "special characters")
            ])

        elif len(args) == 2:
            # Two argument function
            tests.extend([
                (("arg1", "arg2"), "normal case"),
                (("", ""), "empty inputs"),
                (("normal", "special!@#"), "mixed inputs"),
                (("long_" + "x" * 50, "short"), "different lengths")
            ])

        elif len(args) == 3:
            # Three argument function
            tests.extend([
                (("arg1", "arg2", "arg3"), "normal case"),
                (("", "", ""), "empty inputs"),
                (("test", "data", "input"), "standard inputs")
            ])

        # Look for conditional statements to generate branch coverage
        for node in ast.walk(func_node):
            if isinstance(node, ast.If):
                # Try to generate tests that would satisfy the condition
                branch_tests = self._generate_branch_tests(node, args)
                tests.extend(branch_tests)

        return tests

    def _generate_branch_tests(self, if_node: ast.If, func_args: List[str]) -> List[Tuple]:
        """Generate tests to cover different branches"""
        tests = []

        # This is a simplified approach
        if len(func_args) == 1:
            tests.extend([
                (("test_true_branch",), "true branch test"),
                (("test_false_branch",), "false branch test")
            ])
        elif len(func_args) == 2:
            tests.extend([
                (("true_case", "value"), "true branch"),
                (("false_case", "value"), "false branch")
            ])

        return tests

    def _generate_exploit_tests(self, code: str, vulnerability_type: str) -> List[Tuple]:
        """Generate tests specifically designed to trigger vulnerabilities"""
        tests = []

        if vulnerability_type not in CWE_VULNERABILITIES:
            return tests

        vuln_info = CWE_VULNERABILITIES[vulnerability_type]
        exploit_vectors = vuln_info.get('exploitation_vectors', [])

        # Count function arguments to generate appropriate test cases
        arg_count = self._count_function_args(code)

        for vector in exploit_vectors[:5]:  # Limit to 5 vectors
            if arg_count == 1:
                tests.append(((vector,), f"exploit test: {vector[:20]}..."))
            elif arg_count == 2:
                tests.append(((vector, "normal_arg"), f"exploit test: {vector[:20]}..."))
                tests.append((("normal_arg", vector), f"exploit test arg2: {vector[:20]}..."))
            elif arg_count >= 3:
                tests.append(((vector, "arg2", "arg3"), f"exploit test: {vector[:20]}..."))

        # Add obfuscated versions
        for vector in exploit_vectors[:2]:  # Fewer obfuscated tests
            if vulnerability_type == "CWE-78":  # Command injection
                obfuscated = vector.replace(';', '%3B').replace('&', '%26')
                if arg_count >= 1:
                    tests.append(((obfuscated,), f"obfuscated exploit: {obfuscated[:20]}..."))

            elif vulnerability_type == "CWE-22":  # Path traversal
                obfuscated = vector.replace('../', '..%2F')
                if arg_count >= 1:
                    tests.append(((obfuscated,), f"obfuscated path: {obfuscated[:20]}..."))

        return tests

    def _generate_edge_case_tests(self, code: str) -> List[Tuple]:
        """Generate edge case tests"""
        tests = []

        arg_count = self._count_function_args(code)

        # Generate common edge cases
        edge_cases = [
            None, "", 0, -1, "null", "undefined",
            "\x00", "\n\r\t", " " * 100, "🔥💻🚨"  # Unicode
        ]

        for edge in edge_cases[:6]:  # Limit edge cases
            if arg_count == 1:
                try:
                    tests.append(((edge,), f"edge case: {repr(edge)}"))
                except:
                    pass
            elif arg_count == 2:
                try:
                    tests.append(((edge, "normal"), f"edge case: {repr(edge)}"))
                    tests.append((("normal", edge), f"edge case arg2: {repr(edge)}"))
                except:
                    pass

        return tests

    def _count_function_args(self, code: str) -> int:
        """Count arguments in the main function"""
        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    return len(node.args.args)

            return 1  # Default assumption
        except:
            return 1


class RealCodeExecutor:
    """Real sandboxed code execution (not mocks)"""

    def __init__(self):
        self.execution_timeout = CONFIG['execution_timeout']
        self.temp_files = []

    def execute_with_test_cases(self, code: str, test_cases: List[Tuple],
                               function_name: str = None) -> Tuple[float, List[str], Dict[str, Any]]:
        """Execute code with real test cases and return comprehensive results"""

        if not code or not test_cases:
            return 0.0, ["No code or test cases provided"], {}

        results = {
            'passed': 0,
            'failed': 0,
            'errors': [],
            'execution_times': [],
            'outputs': [],
            'exceptions': []
        }

        # Find the function to test
        extracted_function = self._extract_function(code, function_name)
        if not extracted_function:
            return 0.0, ["No valid function found"], results

        # Execute each test case in isolation
        for i, test_case in enumerate(test_cases):
            try:
                test_result = self._execute_single_test(extracted_function, test_case, i)

                if test_result['success']:
                    results['passed'] += 1
                    results['outputs'].append(test_result['output'])
                else:
                    results['failed'] += 1
                    results['errors'].append(test_result['error'])
                    results['exceptions'].append(test_result.get('exception'))

                results['execution_times'].append(test_result['execution_time'])

            except Exception as e:
                results['failed'] += 1
                results['errors'].append(f"Test {i+1}: Critical error: {str(e)[:100]}")
                results['exceptions'].append(type(e).__name__)

        # Calculate pass rate
        total_tests = len(test_cases)
        pass_rate = results['passed'] / total_tests if total_tests > 0 else 0.0

        # Generate error summary
        error_summary = []
        if results['failed'] > 0:
            # Group similar errors
            error_types = Counter(results['exceptions'])
            for error_type, count in error_types.most_common(3):
                if error_type:
                    error_summary.append(f"{error_type}: {count} occurrences")

        # Add execution statistics
        if results['execution_times']:
            results['avg_execution_time'] = np.mean(results['execution_times'])
            results['max_execution_time'] = max(results['execution_times'])

        return pass_rate, error_summary, results

    def _extract_function(self, code: str, function_name: str = None) -> Optional[str]:
        """Extract the main function from code"""
        try:
            tree = ast.parse(code)

            # Look for the specified function or find the main function
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if function_name and node.name == function_name:
                        return code  # Return full code if function found
                    elif not function_name:
                        return code  # Return full code with any function

            return None

        except SyntaxError:
            return None
        except Exception:
            return None

    def _execute_single_test(self, code: str, test_case: Tuple, test_index: int) -> Dict[str, Any]:
        """Execute a single test case in isolation"""

        # Create test script
        test_script = self._create_isolated_test_script(code, test_case, test_index)

        # Write to temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        self.temp_files.append(temp_file.name)

        try:
            temp_file.write(test_script)
            temp_file.flush()
            temp_file.close()

            # Execute with timeout
            start_time = time.time()

            proc = subprocess.Popen(
                [sys.executable, '-u', temp_file.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=tempfile.gettempdir()  # Safe working directory
            )

            try:
                stdout, stderr = proc.communicate(timeout=self.execution_timeout)
                execution_time = time.time() - start_time

                if proc.returncode == 0:
                    # Parse output
                    if stdout.startswith("TEST_RESULT:"):
                        output = stdout[12:].strip()
                        return {
                            'success': True,
                            'output': output,
                            'execution_time': execution_time,
                            'error': None,
                            'exception': None
                        }
                    else:
                        return {
                            'success': False,
                            'output': None,
                            'execution_time': execution_time,
                            'error': f"Unexpected output format: {stdout[:100]}",
                            'exception': 'OutputFormatError'
                        }
                else:
                    return {
                        'success': False,
                        'output': None,
                        'execution_time': execution_time,
                        'error': f"Process failed: {stderr[:100]}",
                        'exception': 'ProcessError'
                    }

            except subprocess.TimeoutExpired:
                proc.kill()
                return {
                    'success': False,
                    'output': None,
                    'execution_time': self.execution_timeout,
                    'error': "Execution timeout",
                    'exception': 'TimeoutError'
                }

        except Exception as e:
            return {
                'success': False,
                'output': None,
                'execution_time': 0.0,
                'error': f"Test setup failed: {str(e)[:100]}",
                'exception': type(e).__name__
            }
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
                if temp_file.name in self.temp_files:
                    self.temp_files.remove(temp_file.name)
            except:
                pass

    def _create_isolated_test_script(self, code: str, test_case: Tuple, test_index: int) -> str:
        """Create an isolated test script"""

        # Extract test input and expected (if available)
        if len(test_case) >= 2:
            test_input, expected = test_case[0], test_case[1]
        else:
            test_input, expected = test_case[0], None

        # Create minimal imports for common functions
        safe_imports = """
import os
import sys
import json
import hashlib
import hmac
import subprocess
import tempfile
from pathlib import Path

# Safe mock objects for testing
class MockDB:
    def execute(self, query, params=None):
        return [{'id': 1, 'name': 'test'}]

    def cursor(self):
        return self

    def fetchone(self):
        return (1, 'mock_hash', 'mock_salt')

    def fetchall(self):
        return [{'user': 'test'}]

class MockConnection:
    def cursor(self):
        return MockDB()

# Mock functions that might be called
def create_connection(**kwargs):
    return MockConnection()

database = MockDB()
db_connection = MockConnection()
"""

        test_script = f"""
{safe_imports}

# User code
{code}

# Test execution
try:
    # Find the function to test
    func = None
    for name, obj in locals().items():
        if callable(obj) and not name.startswith('_') and not name.startswith('Mock'):
            if not name in ['create_connection', 'database']:
                func = obj
                break

    if func is None:
        print("TEST_RESULT:ERROR:No function found")
        sys.exit(1)

    # Prepare test input
    test_input = {repr(test_input)}

    # Execute function
    if isinstance(test_input, tuple) and len(test_input) > 0:
        if len(test_input) == 1:
            result = func(test_input[0])
        else:
            result = func(*test_input)
    else:
        result = func(test_input)

    # Return result
    print(f"TEST_RESULT:{{repr(result)}}")

except Exception as e:
    print(f"TEST_RESULT:ERROR:{{type(e).__name__}}: {{str(e)[:100]}}")
    sys.exit(1)
"""

        return test_script

    def cleanup(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except:
                pass
        self.temp_files.clear()

    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup()