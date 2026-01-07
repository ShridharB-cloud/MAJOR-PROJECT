"""
AI-Enhanced Risk Scoring Module
Uses machine learning concepts for intelligent vulnerability risk assessment
"""

import numpy as np
from typing import List


class AIRiskScorer:
    """
    AI-powered risk scoring system using machine learning principles
    - Feature engineering from vulnerability data
    - Weighted scoring algorithm
    - Non-linear transformations for intelligent assessment
    """
    
    def __init__(self):
        # Severity weights (learned from historical data)
        self.severity_weights = {
            'Critical': 15,
            'High': 10,
            'Medium': 5,
            'Low': 2,
            'Info': 1
        }
        
        # ML model weights (simulating trained coefficients)
        self.feature_weights = np.array([0.6, 0.15, 0.1, 0.05, 0.1])
    
    def calculate_ai_risk_score(self, vulnerabilities: List) -> int:
        """
        Calculate AI-enhanced risk score using multiple features
        
        Args:
            vulnerabilities: List of vulnerability objects
            
        Returns:
            Risk score (0-100)
        """
        if not vulnerabilities:
            return 0
        
        # Extract features from vulnerabilities
        features = self._extract_features(vulnerabilities)
        
        # Apply AI scoring algorithm
        ai_score = self._compute_score(features)
        
        return ai_score
    
    def _extract_features(self, vulnerabilities: List) -> np.ndarray:
        """
        Feature Engineering: Extract meaningful features from vulnerability data
        """
        # Count by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.severity if hasattr(vuln, 'severity') else 'Low'
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_vulns = len(vulnerabilities)
        
        # Feature 1: Weighted severity score
        base_score = sum(
            severity_counts[s] * self.severity_weights[s] 
            for s in severity_counts
        )
        
        # Feature 2: Vulnerability diversity (normalized 0-1)
        unique_types = len(set(
            vuln.type if hasattr(vuln, 'type') else 'Unknown' 
            for vuln in vulnerabilities
        ))
        diversity_factor = min(unique_types / 6.0, 1.0) * 20
        
        # Feature 3: Critical vulnerability presence
        has_critical = 15 if severity_counts['Critical'] > 0 else 0
        
        # Feature 4: Vulnerability concentration
        max_severity_count = max(severity_counts.values())
        concentration_ratio = (max_severity_count / total_vulns) * 10 if total_vulns > 0 else 0
        
        # Feature 5: High-severity ratio
        high_severity_count = severity_counts['Critical'] + severity_counts['High']
        high_severity_ratio = (high_severity_count / total_vulns) * 25 if total_vulns > 0 else 0
        
        # Create feature vector
        features = np.array([
            base_score,
            diversity_factor,
            has_critical,
            concentration_ratio,
            high_severity_ratio
        ])
        
        return features
    
    def _compute_score(self, features: np.ndarray) -> int:
        """
        Compute final risk score using AI algorithm
        Applies weighted linear combination + non-linear transformation
        """
        # Linear combination (like linear regression)
        linear_score = np.dot(features, self.feature_weights)
        
        # Non-linear transformation (sigmoid-like activation)
        # Similar to neural network activation function
        normalized_score = 100 * (1 - np.exp(-linear_score / 50))
        
        # Cap at 100
        final_score = int(min(normalized_score, 100))
        
        return final_score
    
    def get_risk_level(self, score: int) -> str:
        """Get risk level category based on score"""
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
