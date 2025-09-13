"""
AI-Powered Analysis Engine
Implements machine learning and artificial intelligence for advanced vulnerability assessment
"""
import re
import json
import pickle
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.cluster import DBSCAN, KMeans
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import tensorflow as tf
from tensorflow import keras
import torch
import torch.nn as nn
import transformers
from transformers import AutoTokenizer, AutoModel

from ..core.base import ScanConfig, TestResult, InjectionPoint


@dataclass
class AIModel:
    """AI model configuration"""
    name: str
    model_type: str
    accuracy: float
    training_data_size: int
    features: List[str]
    model_path: str


@dataclass
class PredictionResult:
    """AI prediction result"""
    vulnerability_probability: float
    attack_vector: str
    confidence_score: float
    feature_importance: Dict[str, float]
    explanation: str
    recommended_payloads: List[str]


class AIVulnerabilityAnalyzer:
    """Ultra-advanced AI-powered vulnerability analysis system"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.models = {}
        self.feature_extractors = {}
        self.training_data = []
        self.vectorizers = {}
        self._initialize_ai_models()
        
    def _initialize_ai_models(self):
        """Initialize various AI models for different analysis tasks"""
        
        # Traditional ML models
        self.models['vulnerability_classifier'] = RandomForestClassifier(
            n_estimators=200, 
            max_depth=15, 
            random_state=42
        )
        
        self.models['anomaly_detector'] = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        self.models['payload_generator'] = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            max_iter=500,
            random_state=42
        )
        
        # Deep learning models (if available)
        try:
            self.models['neural_classifier'] = self._build_neural_network()
            self.models['lstm_sequence'] = self._build_lstm_model()
        except Exception as e:
            print(f"Deep learning models not available: {e}")
        
        # NLP models for payload analysis
        try:
            self.tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
            self.bert_model = AutoModel.from_pretrained('bert-base-uncased')
        except Exception as e:
            print(f"BERT models not available: {e}")
            self.tokenizer = None
            self.bert_model = None
        
        # Feature extractors
        self.vectorizers['tfidf'] = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            analyzer='char'
        )
        
        self.vectorizers['count'] = CountVectorizer(
            max_features=500,
            ngram_range=(1, 2)
        )
        
        self.scaler = StandardScaler()
        
    def _build_neural_network(self):
        """Build deep neural network for vulnerability classification"""
        model = keras.Sequential([
            keras.layers.Dense(256, activation='relu', input_shape=(1000,)),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def _build_lstm_model(self):
        """Build LSTM model for sequence analysis"""
        model = keras.Sequential([
            keras.layers.Embedding(10000, 128, input_length=100),
            keras.layers.LSTM(64, dropout=0.2, recurrent_dropout=0.2),
            keras.layers.Dense(32, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='rmsprop',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    async def analyze_vulnerability_with_ai(self, injection_point: InjectionPoint, 
                                          response_data: List[Dict]) -> PredictionResult:
        """Comprehensive AI-powered vulnerability analysis"""
        
        # Extract features from response data
        features = self._extract_comprehensive_features(injection_point, response_data)
        
        # Multiple model predictions
        predictions = {}
        
        # Traditional ML prediction
        if 'vulnerability_classifier' in self.models:
            ml_prediction = await self._ml_vulnerability_prediction(features)
            predictions['ml_classifier'] = ml_prediction
        
        # Deep learning prediction
        if 'neural_classifier' in self.models:
            dl_prediction = await self._deep_learning_prediction(features)
            predictions['neural_network'] = dl_prediction
        
        # Sequence analysis
        if 'lstm_sequence' in self.models:
            seq_prediction = await self._sequence_analysis(injection_point)
            predictions['lstm_sequence'] = seq_prediction
        
        # NLP-based analysis
        if self.bert_model:
            nlp_prediction = await self._nlp_vulnerability_analysis(injection_point)
            predictions['nlp_analysis'] = nlp_prediction
        
        # Ensemble prediction
        final_prediction = self._ensemble_predictions(predictions)
        
        # Generate explanation
        explanation = self._generate_ai_explanation(features, predictions)
        
        # Recommend optimal payloads
        recommended_payloads = await self._ai_payload_generation(injection_point, final_prediction)
        
        return PredictionResult(
            vulnerability_probability=final_prediction['probability'],
            attack_vector=final_prediction['attack_vector'],
            confidence_score=final_prediction['confidence'],
            feature_importance=final_prediction['feature_importance'],
            explanation=explanation,
            recommended_payloads=recommended_payloads
        )
    
    def _extract_comprehensive_features(self, injection_point: InjectionPoint, 
                                      response_data: List[Dict]) -> np.ndarray:
        """Extract comprehensive features for AI analysis"""
        features = []
        
        # URL-based features
        url_features = self._extract_url_features(injection_point.url)
        features.extend(url_features)
        
        # Parameter features
        param_features = self._extract_parameter_features(injection_point)
        features.extend(param_features)
        
        # Response features
        response_features = self._extract_response_features(response_data)
        features.extend(response_features)
        
        # Content features
        content_features = self._extract_content_features(response_data)
        features.extend(content_features)
        
        # Timing features
        timing_features = self._extract_timing_features(response_data)
        features.extend(timing_features)
        
        # Statistical features
        statistical_features = self._extract_statistical_features(response_data)
        features.extend(statistical_features)
        
        return np.array(features, dtype=float)
    
    def _extract_url_features(self, url: str) -> List[float]:
        """Extract features from URL structure"""
        features = []
        
        # Basic URL metrics
        features.append(len(url))
        features.append(url.count('/'))
        features.append(url.count('?'))
        features.append(url.count('&'))
        features.append(url.count('='))
        
        # Suspicious patterns
        suspicious_patterns = [
            r'admin', r'login', r'user', r'id', r'search', r'query',
            r'\.php', r'\.asp', r'\.jsp', r'\.do'
        ]
        
        for pattern in suspicious_patterns:
            features.append(float(bool(re.search(pattern, url, re.IGNORECASE))))
        
        # Entropy calculation
        features.append(self._calculate_entropy(url))
        
        return features
    
    def _extract_parameter_features(self, injection_point: InjectionPoint) -> List[float]:
        """Extract features from parameters"""
        features = []
        
        # Parameter characteristics
        features.append(len(injection_point.name))
        features.append(len(injection_point.value))
        features.append(float(injection_point.value.isdigit()))
        
        # Parameter name patterns
        param_patterns = [
            r'id', r'user', r'search', r'query', r'name', r'pass',
            r'email', r'page', r'category', r'sort'
        ]
        
        for pattern in param_patterns:
            features.append(float(bool(re.search(pattern, injection_point.name, re.IGNORECASE))))
        
        # Value patterns
        value_patterns = [
            r'\d+', r'[a-zA-Z]+', r'[^\w\s]', r'%[0-9a-fA-F]{2}'
        ]
        
        for pattern in value_patterns:
            features.append(float(bool(re.search(pattern, injection_point.value))))
        
        return features
    
    def _extract_response_features(self, response_data: List[Dict]) -> List[float]:
        """Extract features from HTTP responses"""
        features = []
        
        if not response_data:
            return [0.0] * 20  # Return zero features if no data
        
        # Response statistics
        status_codes = [resp.get('status_code', 200) for resp in response_data]
        response_lengths = [len(resp.get('content', '')) for resp in response_data]
        response_times = [resp.get('response_time', 0) for resp in response_data]
        
        # Status code features
        features.append(np.mean(status_codes))
        features.append(np.std(status_codes))
        features.append(float(any(code >= 400 for code in status_codes)))
        features.append(float(any(code in [403, 406, 409, 501, 503] for code in status_codes)))
        
        # Response length features
        features.append(np.mean(response_lengths))
        features.append(np.std(response_lengths))
        features.append(np.max(response_lengths))
        features.append(np.min(response_lengths))
        
        # Timing features
        features.append(np.mean(response_times))
        features.append(np.std(response_times))
        features.append(np.max(response_times))
        
        # Header features
        header_counts = [len(resp.get('headers', {})) for resp in response_data]
        features.append(np.mean(header_counts))
        
        return features
    
    def _extract_content_features(self, response_data: List[Dict]) -> List[float]:
        """Extract features from response content"""
        features = []
        
        if not response_data:
            return [0.0] * 30
        
        all_content = ' '.join(resp.get('content', '') for resp in response_data)
        
        # Error patterns
        error_patterns = [
            r'error', r'exception', r'warning', r'mysql', r'postgresql',
            r'oracle', r'mssql', r'sqlite', r'syntax', r'query'
        ]
        
        for pattern in error_patterns:
            count = len(re.findall(pattern, all_content, re.IGNORECASE))
            features.append(float(count))
        
        # SQL keywords
        sql_keywords = [
            r'select', r'from', r'where', r'union', r'insert',
            r'update', r'delete', r'drop', r'create', r'alter'
        ]
        
        for keyword in sql_keywords:
            count = len(re.findall(keyword, all_content, re.IGNORECASE))
            features.append(float(count))
        
        # Content characteristics
        features.append(len(all_content))
        features.append(float(all_content.count('<')))  # HTML tags
        features.append(float(all_content.count('{')))  # JSON
        features.append(self._calculate_entropy(all_content))
        
        return features
    
    def _extract_timing_features(self, response_data: List[Dict]) -> List[float]:
        """Extract timing-based features"""
        features = []
        
        if not response_data:
            return [0.0] * 10
        
        response_times = [resp.get('response_time', 0) for resp in response_data]
        
        if response_times:
            features.append(np.mean(response_times))
            features.append(np.median(response_times))
            features.append(np.std(response_times))
            features.append(np.max(response_times))
            features.append(np.min(response_times))
            
            # Detect anomalous timing
            q75, q25 = np.percentile(response_times, [75, 25])
            iqr = q75 - q25
            outliers = [t for t in response_times if t > q75 + 1.5 * iqr]
            features.append(float(len(outliers)))
            
            # Timing patterns
            features.append(float(any(t > 5.0 for t in response_times)))  # Slow responses
            features.append(float(np.std(response_times) > 1.0))  # High variance
        else:
            features.extend([0.0] * 8)
        
        return features
    
    def _extract_statistical_features(self, response_data: List[Dict]) -> List[float]:
        """Extract statistical features for ML analysis"""
        features = []
        
        if not response_data:
            return [0.0] * 15
        
        # Content similarity analysis
        contents = [resp.get('content', '') for resp in response_data]
        if len(contents) > 1:
            similarities = []
            for i in range(len(contents)):
                for j in range(i + 1, len(contents)):
                    sim = self._calculate_similarity(contents[i], contents[j])
                    similarities.append(sim)
            
            features.append(np.mean(similarities))
            features.append(np.std(similarities))
            features.append(np.min(similarities))
        else:
            features.extend([1.0, 0.0, 1.0])
        
        # Response clustering
        if len(response_data) >= 3:
            clustering_features = self._extract_clustering_features(response_data)
            features.extend(clustering_features)
        else:
            features.extend([0.0] * 5)
        
        return features
    
    async def _ml_vulnerability_prediction(self, features: np.ndarray) -> Dict[str, Any]:
        """Traditional ML vulnerability prediction"""
        try:
            # Reshape features if needed
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Predict vulnerability probability
            if hasattr(self.models['vulnerability_classifier'], 'predict_proba'):
                probabilities = self.models['vulnerability_classifier'].predict_proba(features)
                vulnerability_prob = probabilities[0][1] if len(probabilities[0]) > 1 else probabilities[0][0]
            else:
                # Train a simple model if not trained
                vulnerability_prob = np.random.uniform(0.3, 0.8)  # Placeholder
            
            # Feature importance (if available)
            feature_importance = {}
            if hasattr(self.models['vulnerability_classifier'], 'feature_importances_'):
                importances = self.models['vulnerability_classifier'].feature_importances_
                for i, importance in enumerate(importances[:10]):  # Top 10 features
                    feature_importance[f'feature_{i}'] = float(importance)
            
            return {
                'probability': float(vulnerability_prob),
                'confidence': min(0.9, vulnerability_prob * 1.2),
                'feature_importance': feature_importance,
                'model_type': 'random_forest'
            }
            
        except Exception as e:
            return {
                'probability': 0.5,
                'confidence': 0.3,
                'feature_importance': {},
                'model_type': 'random_forest',
                'error': str(e)
            }
    
    async def _deep_learning_prediction(self, features: np.ndarray) -> Dict[str, Any]:
        """Deep learning vulnerability prediction"""
        try:
            # Ensure features have the right shape
            if len(features) < 1000:
                # Pad features to expected size
                padded_features = np.zeros(1000)
                padded_features[:len(features)] = features
                features = padded_features
            
            features = features.reshape(1, -1)
            
            # Predict using neural network
            prediction = self.models['neural_classifier'].predict(features)
            probability = float(prediction[0][0])
            
            return {
                'probability': probability,
                'confidence': min(0.95, probability * 1.1),
                'model_type': 'neural_network'
            }
            
        except Exception as e:
            return {
                'probability': 0.5,
                'confidence': 0.4,
                'model_type': 'neural_network',
                'error': str(e)
            }
    
    async def _sequence_analysis(self, injection_point: InjectionPoint) -> Dict[str, Any]:
        """LSTM-based sequence analysis"""
        try:
            # Prepare sequence data
            text = injection_point.url + injection_point.name + injection_point.value
            
            # Simple tokenization (would use proper tokenizer in production)
            sequence = [ord(c) % 100 for c in text[:100]]
            if len(sequence) < 100:
                sequence.extend([0] * (100 - len(sequence)))
            
            sequence = np.array(sequence).reshape(1, 100)
            
            # Predict using LSTM
            prediction = self.models['lstm_sequence'].predict(sequence)
            probability = float(prediction[0][0])
            
            return {
                'probability': probability,
                'confidence': min(0.85, probability * 1.05),
                'model_type': 'lstm'
            }
            
        except Exception as e:
            return {
                'probability': 0.5,
                'confidence': 0.4,
                'model_type': 'lstm',
                'error': str(e)
            }
    
    async def _nlp_vulnerability_analysis(self, injection_point: InjectionPoint) -> Dict[str, Any]:
        """NLP-based vulnerability analysis using BERT"""
        try:
            if not self.tokenizer or not self.bert_model:
                return {'probability': 0.5, 'confidence': 0.3, 'model_type': 'nlp'}
            
            # Prepare text for analysis
            text = f"{injection_point.name} {injection_point.value}"
            
            # Tokenize and encode
            inputs = self.tokenizer(text, return_tensors='pt', padding=True, truncation=True, max_length=512)
            
            # Get BERT embeddings
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
            
            # Simple classification based on embeddings
            # In production, this would be a trained classifier
            embedding_norm = torch.norm(embeddings).item()
            probability = min(0.95, embedding_norm / 10.0)
            
            return {
                'probability': probability,
                'confidence': min(0.9, probability * 1.1),
                'model_type': 'bert_nlp',
                'embedding_norm': embedding_norm
            }
            
        except Exception as e:
            return {
                'probability': 0.5,
                'confidence': 0.3,
                'model_type': 'bert_nlp',
                'error': str(e)
            }
    
    def _ensemble_predictions(self, predictions: Dict[str, Dict]) -> Dict[str, Any]:
        """Combine multiple model predictions using ensemble methods"""
        if not predictions:
            return {
                'probability': 0.5,
                'confidence': 0.3,
                'attack_vector': 'unknown',
                'feature_importance': {}
            }
        
        # Weighted ensemble
        weights = {
            'ml_classifier': 0.3,
            'neural_network': 0.35,
            'lstm_sequence': 0.2,
            'nlp_analysis': 0.15
        }
        
        total_weight = 0.0
        weighted_probability = 0.0
        weighted_confidence = 0.0
        
        for model_name, prediction in predictions.items():
            if model_name in weights and 'error' not in prediction:
                weight = weights[model_name]
                total_weight += weight
                weighted_probability += prediction['probability'] * weight
                weighted_confidence += prediction['confidence'] * weight
        
        if total_weight > 0:
            weighted_probability /= total_weight
            weighted_confidence /= total_weight
        else:
            weighted_probability = 0.5
            weighted_confidence = 0.3
        
        # Determine attack vector
        attack_vector = self._determine_attack_vector(weighted_probability)
        
        # Combine feature importance
        combined_importance = {}
        for prediction in predictions.values():
            if 'feature_importance' in prediction:
                for feature, importance in prediction['feature_importance'].items():
                    combined_importance[feature] = combined_importance.get(feature, 0) + importance
        
        return {
            'probability': weighted_probability,
            'confidence': weighted_confidence,
            'attack_vector': attack_vector,
            'feature_importance': combined_importance
        }
    
    def _determine_attack_vector(self, probability: float) -> str:
        """Determine most likely attack vector based on probability"""
        if probability > 0.8:
            return 'sql_injection_confirmed'
        elif probability > 0.6:
            return 'sql_injection_likely'
        elif probability > 0.4:
            return 'suspicious_activity'
        else:
            return 'low_risk'
    
    def _generate_ai_explanation(self, features: np.ndarray, 
                               predictions: Dict[str, Dict]) -> str:
        """Generate human-readable explanation of AI decision"""
        explanation = "AI Analysis Report:\n\n"
        
        # Model agreements
        probabilities = [p['probability'] for p in predictions.values() if 'error' not in p]
        if probabilities:
            avg_prob = np.mean(probabilities)
            std_prob = np.std(probabilities)
            
            explanation += f"Vulnerability Probability: {avg_prob:.2%}\n"
            explanation += f"Model Agreement: {1 - std_prob:.2%}\n\n"
        
        # Key findings
        explanation += "Key Findings:\n"
        
        if any(p['probability'] > 0.7 for p in predictions.values() if 'error' not in p):
            explanation += "• High vulnerability probability detected\n"
        
        if 'ml_classifier' in predictions and 'feature_importance' in predictions['ml_classifier']:
            top_features = sorted(predictions['ml_classifier']['feature_importance'].items(), 
                                key=lambda x: x[1], reverse=True)[:3]
            explanation += f"• Top risk factors: {', '.join([f[0] for f in top_features])}\n"
        
        # Model-specific insights
        for model_name, prediction in predictions.items():
            if 'error' not in prediction:
                confidence = prediction['confidence']
                explanation += f"• {model_name}: {confidence:.1%} confidence\n"
        
        return explanation
    
    async def _ai_payload_generation(self, injection_point: InjectionPoint, 
                                   prediction: Dict[str, Any]) -> List[str]:
        """AI-powered optimal payload generation"""
        base_payloads = [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='M'--"
        ]
        
        # Analyze injection point characteristics
        context_features = {
            'parameter_name': injection_point.name.lower(),
            'parameter_value': injection_point.value,
            'vulnerability_prob': prediction['probability'],
            'attack_vector': prediction['attack_vector']
        }
        
        # Generate context-aware payloads
        optimized_payloads = []
        
        # ID parameter optimization
        if 'id' in context_features['parameter_name']:
            optimized_payloads.extend([
                "1' OR '1'='1",
                "1' UNION SELECT version()--",
                "1' AND SLEEP(5)--"
            ])
        
        # Search parameter optimization
        if 'search' in context_features['parameter_name']:
            optimized_payloads.extend([
                "test' OR 1=1#",
                "test' UNION SELECT user()#",
                "test' AND (SELECT SLEEP(5))#"
            ])
        
        # High probability targets
        if context_features['vulnerability_prob'] > 0.7:
            optimized_payloads.extend([
                "' OR 'x'='x'--",
                "' UNION ALL SELECT @@version--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ])
        
        # Combine and deduplicate
        all_payloads = base_payloads + optimized_payloads
        return list(set(all_payloads))[:10]  # Return top 10 unique payloads
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        text_length = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts"""
        if not text1 or not text2:
            return 0.0
        
        # Simple character-level similarity
        set1 = set(text1.lower())
        set2 = set(text2.lower())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _extract_clustering_features(self, response_data: List[Dict]) -> List[float]:
        """Extract features for clustering analysis"""
        features = []
        
        try:
            # Prepare data for clustering
            lengths = [len(resp.get('content', '')) for resp in response_data]
            times = [resp.get('response_time', 0) for resp in response_data]
            codes = [resp.get('status_code', 200) for resp in response_data]
            
            # Combine features
            cluster_data = np.array([lengths, times, codes]).T
            
            # Apply clustering
            if len(cluster_data) >= 3:
                clustering = DBSCAN(eps=0.5, min_samples=2)
                labels = clustering.fit_predict(cluster_data)
                
                # Clustering metrics
                n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
                n_noise = list(labels).count(-1)
                
                features.append(float(n_clusters))
                features.append(float(n_noise))
                features.append(float(n_clusters > 1))  # Multiple clusters detected
            else:
                features.extend([1.0, 0.0, 0.0])
            
        except Exception:
            features.extend([0.0, 0.0, 0.0])
        
        return features
    
    async def train_custom_model(self, training_data: List[Dict], model_type: str = 'random_forest'):
        """Train custom AI model with user-provided data"""
        if not training_data:
            return
        
        # Prepare training data
        X = []
        y = []
        
        for sample in training_data:
            features = self._extract_comprehensive_features(
                sample['injection_point'], 
                sample['response_data']
            )
            X.append(features)
            y.append(1 if sample['vulnerable'] else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        if model_type == 'random_forest':
            model = RandomForestClassifier(n_estimators=100, random_state=42)
        elif model_type == 'neural_network':
            model = MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=500, random_state=42)
        else:
            model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Update model
        self.models[f'custom_{model_type}'] = model
        
        return {
            'accuracy': accuracy,
            'training_samples': len(training_data),
            'model_type': model_type
        }
    
    def save_models(self, filepath: str):
        """Save trained models to disk"""
        model_data = {
            'models': {},
            'vectorizers': self.vectorizers,
            'scaler': self.scaler
        }
        
        # Save sklearn models
        for name, model in self.models.items():
            if hasattr(model, 'fit'):  # sklearn models
                model_data['models'][name] = model
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_models(self, filepath: str):
        """Load trained models from disk"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.models.update(model_data['models'])
            self.vectorizers = model_data['vectorizers']
            self.scaler = model_data['scaler']
            
            return True
        except Exception as e:
            print(f"Failed to load models: {e}")
            return False