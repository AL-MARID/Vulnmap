"""
Machine Learning-based Anomaly Detection Module
Detects anomalous patterns in web application behavior
"""
import json
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import hashlib
from utils.logger import get_logger
logger = get_logger(__name__)
class MLAnomalyDetector:
    """Machine learning-based anomaly detection for security testing."""
    def __init__(self, config: Dict):
        """Initialize ML anomaly detector."""
        self.config = config
        self.baseline_data = defaultdict(list)
        self.anomaly_threshold = config.get('ml_config', {}).get('anomaly_threshold', 0.7)
        self.min_samples = config.get('ml_config', {}).get('min_samples', 10)
    def train_baseline(self, responses: List[Dict]) -> None:
        """
        Train baseline model from normal responses.
        Args:
            responses: List of normal HTTP responses
        """
        logger.info(f"Training baseline model with {len(responses)} samples")
        for response in responses:
            features = self._extract_features(response)
            for feature_name, feature_value in features.items():
                self.baseline_data[feature_name].append(feature_value)
        logger.info("Baseline training completed")
    def detect_anomalies(self, response: Dict) -> List[Dict]:
        """
        Detect anomalies in a response.
        Args:
            response: HTTP response to analyze
        Returns:
            List of detected anomalies
        """
        anomalies = []
        if len(self.baseline_data) == 0:
            logger.warning("No baseline data available. Train model first.")
            return anomalies
        features = self._extract_features(response)
        for feature_name, feature_value in features.items():
            if feature_name in self.baseline_data:
                is_anomalous, score = self._is_anomalous(
                    feature_name, 
                    feature_value, 
                    self.baseline_data[feature_name]
                )
                if is_anomalous:
                    anomalies.append({
                        'type': 'ML Anomaly Detection',
                        'severity': self._calculate_severity(score),
                        'feature': feature_name,
                        'value': feature_value,
                        'anomaly_score': score,
                        'evidence': f'Anomalous {feature_name}: {feature_value}',
                        'description': f'Machine learning detected unusual {feature_name}',
                        'remediation': 'Investigate the anomalous behavior for security implications'
                    })
        return anomalies
    def _extract_features(self, response: Dict) -> Dict:
        """Extract features from HTTP response for ML analysis."""
        features = {}
        if 'response_time' in response:
            features['response_time'] = response['response_time']
        if 'content' in response:
            features['response_size'] = len(str(response['content']))
        if 'status_code' in response:
            features['status_code'] = response['status_code']
        if 'headers' in response:
            features['header_count'] = len(response['headers'])
        if 'headers' in response and 'Content-Type' in response['headers']:
            features['content_type'] = response['headers']['Content-Type']
        if 'content' in response:
            features['content_entropy'] = self._calculate_entropy(str(response['content']))
        if 'content' in response:
            features['error_pattern'] = self._detect_error_patterns(str(response['content']))
        if 'redirect_count' in response:
            features['redirect_count'] = response['redirect_count']
        return features
    def _is_anomalous(self, feature_name: str, value, baseline_values: List) -> Tuple[bool, float]:
        """
        Determine if a feature value is anomalous.
        Args:
            feature_name: Name of the feature
            value: Current value
            baseline_values: Historical baseline values
        Returns:
            Tuple of (is_anomalous, anomaly_score)
        """
        if len(baseline_values) < self.min_samples:
            return False, 0.0
        if isinstance(value, (int, float)):
            return self._detect_numeric_anomaly(value, baseline_values)
        elif isinstance(value, str):
            return self._detect_categorical_anomaly(value, baseline_values)
        return False, 0.0
    def _detect_numeric_anomaly(self, value: float, baseline: List[float]) -> Tuple[bool, float]:
        """Detect anomalies in numeric features using statistical methods."""
        import statistics
        try:
            mean = statistics.mean(baseline)
            stdev = statistics.stdev(baseline) if len(baseline) > 1 else 0
            if stdev == 0:
                return False, 0.0
            z_score = abs((value - mean) / stdev)
            is_anomalous = z_score > 3
            anomaly_score = min(z_score / 10, 1.0)  # Normalize to 0-1
            return is_anomalous, anomaly_score
        except Exception as e:
            logger.debug(f"Error in numeric anomaly detection: {e}")
            return False, 0.0
    def _detect_categorical_anomaly(self, value: str, baseline: List[str]) -> Tuple[bool, float]:
        """Detect anomalies in categorical features using frequency analysis."""
        value_counts = defaultdict(int)
        for v in baseline:
            value_counts[v] += 1
        total_count = len(baseline)
        value_frequency = value_counts.get(value, 0) / total_count
        is_anomalous = value_frequency < 0.1
        anomaly_score = 1.0 - value_frequency if is_anomalous else 0.0
        return is_anomalous, anomaly_score
    def _calculate_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of content."""
        if not content:
            return 0.0
        import math
        frequencies = defaultdict(int)
        for char in content:
            frequencies[char] += 1
        entropy = 0.0
        content_length = len(content)
        for count in frequencies.values():
            probability = count / content_length
            entropy -= probability * math.log2(probability)
        return entropy
    def _detect_error_patterns(self, content: str) -> int:
        """Detect error patterns in content."""
        error_keywords = [
            'exception', 'error', 'warning', 'fatal', 'stack trace',
            'sql error', 'syntax error', 'undefined', 'null pointer',
            'access denied', 'forbidden', 'unauthorized'
        ]
        error_count = 0
        content_lower = content.lower()
        for keyword in error_keywords:
            if keyword in content_lower:
                error_count += 1
        return error_count
    def _calculate_severity(self, anomaly_score: float) -> str:
        """Calculate severity based on anomaly score."""
        if anomaly_score >= 0.8:
            return 'high'
        elif anomaly_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    def analyze_response_patterns(self, responses: List[Dict]) -> Dict:
        """
        Analyze patterns across multiple responses.
        Args:
            responses: List of responses to analyze
        Returns:
            Pattern analysis report
        """
        patterns = {
            'total_responses': len(responses),
            'unique_status_codes': set(),
            'avg_response_time': 0,
            'avg_response_size': 0,
            'error_rate': 0,
            'anomaly_clusters': []
        }
        if not responses:
            return patterns
        total_time = 0
        total_size = 0
        error_count = 0
        for response in responses:
            if 'status_code' in response:
                patterns['unique_status_codes'].add(response['status_code'])
                if response['status_code'] >= 400:
                    error_count += 1
            if 'response_time' in response:
                total_time += response['response_time']
            if 'content' in response:
                total_size += len(str(response['content']))
        patterns['avg_response_time'] = total_time / len(responses)
        patterns['avg_response_size'] = total_size / len(responses)
        patterns['error_rate'] = (error_count / len(responses)) * 100
        patterns['unique_status_codes'] = list(patterns['unique_status_codes'])
        return patterns
    def detect_timing_attacks(self, timing_data: List[Tuple[str, float]]) -> List[Dict]:
        """
        Detect potential timing attack vulnerabilities.
        Args:
            timing_data: List of (input, response_time) tuples
        Returns:
            List of timing attack vulnerabilities
        """
        vulnerabilities = []
        if len(timing_data) < 2:
            return vulnerabilities
        timing_groups = defaultdict(list)
        for input_data, response_time in timing_data:
            input_hash = hashlib.md5(str(input_data).encode()).hexdigest()[:8]
            timing_groups[input_hash].append(response_time)
        import statistics
        for group_id, times in timing_groups.items():
            if len(times) > 1:
                mean_time = statistics.mean(times)
                stdev_time = statistics.stdev(times) if len(times) > 1 else 0
                if stdev_time > mean_time * 0.5:  # 50% variance
                    vulnerabilities.append({
                        'type': 'ML Anomaly - Timing Attack',
                        'severity': 'medium',
                        'evidence': f'Response time variance: {stdev_time:.3f}s (mean: {mean_time:.3f}s)',
                        'description': 'Significant response time variance detected',
                        'remediation': 'Implement constant-time operations for sensitive comparisons',
                        'cwe': 'CWE-208: Observable Timing Discrepancy'
                    })
        return vulnerabilities
    def cluster_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Cluster similar vulnerabilities using ML techniques.
        Args:
            vulnerabilities: List of vulnerabilities
        Returns:
            Clustered vulnerabilities by type
        """
        clusters = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            clusters[vuln_type].append(vuln)
        return dict(clusters)
    def predict_attack_vectors(self, scan_data: Dict) -> List[Dict]:
        """
        Predict potential attack vectors based on scan data.
        Args:
            scan_data: Scan results and context
        Returns:
            List of predicted attack vectors
        """
        predictions = []
        technologies = scan_data.get('technologies', [])
        tech_predictions = {
            'php': ['SQL Injection', 'LFI', 'RFI', 'Command Injection'],
            'java': ['XXE', 'Deserialization', 'SSRF'],
            'node': ['Prototype Pollution', 'NoSQL Injection', 'SSRF'],
            'wordpress': ['Plugin Vulnerabilities', 'Theme Vulnerabilities', 'XML-RPC'],
            'django': ['SSTI', 'SQL Injection', 'CSRF'],
        }
        for tech in technologies:
            tech_lower = tech.lower()
            for platform, attack_vectors in tech_predictions.items():
                if platform in tech_lower:
                    for vector in attack_vectors:
                        predictions.append({
                            'attack_vector': vector,
                            'technology': tech,
                            'confidence': 0.7,
                            'reason': f'Common vulnerability in {tech} applications'
                        })
        return predictions
