"""
Advanced Reporting & Forensics Module
Implements comprehensive reporting, visualization, and forensic analysis
"""
import json
import time
import base64
import datetime
import statistics
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from jinja2 import Template
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from ..core.base import ScanConfig, TestResult, InjectionPoint
from .multi_vector import MultiVectorResult
from .ai_analyzer import PredictionResult


@dataclass
class ForensicEvidence:
    """Forensic evidence data structure"""
    timestamp: str
    attack_vector: str
    payload: str
    response_data: Dict[str, Any]
    success_indicators: List[str]
    confidence_score: float
    impact_assessment: str


@dataclass
class ComplianceReport:
    """Compliance reporting structure"""
    standard: str  # OWASP, PCI-DSS, GDPR, etc.
    findings: List[Dict[str, Any]]
    risk_score: float
    compliance_status: str
    recommendations: List[str]


class AdvancedReportingEngine:
    """Ultra-advanced reporting and forensics engine"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.evidence_chain = []
        self.scan_metadata = {
            'start_time': datetime.datetime.now(),
            'target_info': {},
            'scan_parameters': asdict(config)
        }
        
    def add_forensic_evidence(self, attack_vector: str, payload: str, 
                            response_data: Dict[str, Any], success_indicators: List[str],
                            confidence_score: float, impact_assessment: str):
        """Add forensic evidence to the chain"""
        evidence = ForensicEvidence(
            timestamp=datetime.datetime.now().isoformat(),
            attack_vector=attack_vector,
            payload=payload,
            response_data=response_data,
            success_indicators=success_indicators,
            confidence_score=confidence_score,
            impact_assessment=impact_assessment
        )
        self.evidence_chain.append(evidence)
    
    async def generate_executive_dashboard(self, results: List[TestResult], 
                                         multi_vector_results: List[MultiVectorResult],
                                         ai_predictions: List[PredictionResult]) -> Dict[str, Any]:
        """Generate executive-level security dashboard"""
        
        # Calculate key metrics
        total_tests = len(results) + len(multi_vector_results)
        vulnerabilities_found = len([r for r in results if r.vulnerable]) + \
                              len([r for r in multi_vector_results if r.success])
        
        risk_score = self._calculate_overall_risk_score(results, multi_vector_results, ai_predictions)
        
        # Time-based analysis
        scan_duration = (datetime.datetime.now() - self.scan_metadata['start_time']).total_seconds()
        
        dashboard = {
            'executive_summary': {
                'scan_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target_analyzed': self.config.target_url,
                'scan_duration_minutes': round(scan_duration / 60, 2),
                'total_tests_performed': total_tests,
                'vulnerabilities_discovered': vulnerabilities_found,
                'overall_risk_score': risk_score,
                'security_posture': self._determine_security_posture(risk_score),
                'immediate_action_required': vulnerabilities_found > 0
            },
            'risk_breakdown': self._generate_risk_breakdown(results, multi_vector_results),
            'attack_vector_analysis': self._analyze_attack_vectors(multi_vector_results),
            'ai_insights': self._extract_ai_insights(ai_predictions),
            'compliance_status': await self._assess_compliance_status(results, multi_vector_results),
            'recommendations': self._generate_executive_recommendations(results, multi_vector_results),
            'trend_analysis': self._generate_trend_analysis(),
            'cost_impact': self._calculate_cost_impact(vulnerabilities_found, risk_score)
        }
        
        return dashboard
    
    async def generate_technical_report(self, results: List[TestResult],
                                      multi_vector_results: List[MultiVectorResult],
                                      ai_predictions: List[PredictionResult]) -> Dict[str, Any]:
        """Generate detailed technical analysis report"""
        
        report = {
            'scan_metadata': self.scan_metadata,
            'vulnerability_analysis': {
                'sql_injection_findings': self._analyze_sql_findings(results),
                'multi_vector_findings': self._analyze_multi_vector_findings(multi_vector_results),
                'ai_analysis_results': self._analyze_ai_predictions(ai_predictions)
            },
            'attack_surface_analysis': await self._analyze_attack_surface(results, multi_vector_results),
            'payload_effectiveness': self._analyze_payload_effectiveness(results, multi_vector_results),
            'response_pattern_analysis': self._analyze_response_patterns(results, multi_vector_results),
            'evasion_analysis': self._analyze_evasion_effectiveness(results),
            'database_fingerprinting': self._extract_database_info(results),
            'forensic_timeline': self._create_forensic_timeline(),
            'technical_recommendations': self._generate_technical_recommendations(results, multi_vector_results)
        }
        
        return report
    
    async def generate_compliance_report(self, results: List[TestResult],
                                       multi_vector_results: List[MultiVectorResult],
                                       standard: str = 'OWASP') -> ComplianceReport:
        """Generate compliance-specific report"""
        
        if standard == 'OWASP':
            return await self._generate_owasp_report(results, multi_vector_results)
        elif standard == 'PCI-DSS':
            return await self._generate_pci_report(results, multi_vector_results)
        elif standard == 'GDPR':
            return await self._generate_gdpr_report(results, multi_vector_results)
        elif standard == 'SOX':
            return await self._generate_sox_report(results, multi_vector_results)
        else:
            return await self._generate_generic_compliance_report(results, multi_vector_results, standard)
    
    def generate_visualizations(self, results: List[TestResult],
                              multi_vector_results: List[MultiVectorResult]) -> Dict[str, str]:
        """Generate comprehensive visualizations"""
        
        visualizations = {}
        
        # Risk heatmap
        visualizations['risk_heatmap'] = self._create_risk_heatmap(results, multi_vector_results)
        
        # Attack vector distribution
        visualizations['attack_vectors'] = self._create_attack_vector_chart(multi_vector_results)
        
        # Vulnerability timeline
        visualizations['timeline'] = self._create_vulnerability_timeline(results, multi_vector_results)
        
        # Impact assessment
        visualizations['impact_assessment'] = self._create_impact_chart(results, multi_vector_results)
        
        # Confidence distribution
        visualizations['confidence_distribution'] = self._create_confidence_chart(results, multi_vector_results)
        
        # Database coverage
        visualizations['database_coverage'] = self._create_database_coverage_chart(results)
        
        # Payload success rates
        visualizations['payload_success'] = self._create_payload_success_chart(results)
        
        return visualizations
    
    async def generate_forensic_report(self, results: List[TestResult],
                                     multi_vector_results: List[MultiVectorResult]) -> Dict[str, Any]:
        """Generate detailed forensic analysis report"""
        
        forensic_report = {
            'evidence_chain': [asdict(evidence) for evidence in self.evidence_chain],
            'attack_reconstruction': await self._reconstruct_attacks(results, multi_vector_results),
            'payload_analysis': self._analyze_payloads_forensically(results, multi_vector_results),
            'response_analysis': self._analyze_responses_forensically(results, multi_vector_results),
            'attacker_behavior': self._analyze_attacker_behavior(results, multi_vector_results),
            'indicators_of_compromise': self._extract_iocs(results, multi_vector_results),
            'attribution_analysis': self._perform_attribution_analysis(results, multi_vector_results),
            'digital_signatures': self._create_digital_signatures(),
            'chain_of_custody': self._create_chain_of_custody()
        }
        
        return forensic_report
    
    def export_to_html(self, dashboard: Dict[str, Any], technical_report: Dict[str, Any],
                      visualizations: Dict[str, str], output_file: str = 'security_report.html'):
        """Export comprehensive report to HTML"""
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQL Injection Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .critical { background-color: #f8d7da; border-color: #f5c6cb; }
                .high { background-color: #fff3cd; border-color: #ffeaa7; }
                .medium { background-color: #d1ecf1; border-color: #bee5eb; }
                .low { background-color: #d4edda; border-color: #c3e6cb; }
                .metric { display: inline-block; margin: 10px; padding: 15px; border-radius: 5px; text-align: center; }
                .chart-container { margin: 20px 0; text-align: center; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SQL Injection Security Assessment Report</h1>
                <p>Generated on {{ report_date }}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="metric critical">
                    <h3>{{ vulnerabilities_found }}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
                <div class="metric high">
                    <h3>{{ risk_score }}/10</h3>
                    <p>Risk Score</p>
                </div>
                <div class="metric medium">
                    <h3>{{ total_tests }}</h3>
                    <p>Tests Performed</p>
                </div>
                <div class="metric low">
                    <h3>{{ scan_duration }} min</h3>
                    <p>Scan Duration</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Vulnerability Findings</h2>
                <table>
                    <tr>
                        <th>Vulnerability Type</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Impact</th>
                        <th>Remediation</th>
                    </tr>
                    {% for finding in findings %}
                    <tr>
                        <td>{{ finding.type }}</td>
                        <td class="{{ finding.severity.lower() }}">{{ finding.severity }}</td>
                        <td>{{ finding.confidence }}%</td>
                        <td>{{ finding.impact }}</td>
                        <td>{{ finding.remediation }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div class="section">
                <h2>Attack Vector Analysis</h2>
                <div class="chart-container">
                    {{ attack_vector_chart }}
                </div>
            </div>
            
            <div class="section">
                <h2>Risk Assessment</h2>
                <div class="chart-container">
                    {{ risk_heatmap }}
                </div>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {% for recommendation in recommendations %}
                    <li>{{ recommendation }}</li>
                    {% endfor %}
                </ul>
            </div>
            
            <div class="section">
                <h2>Technical Details</h2>
                <pre>{{ technical_details }}</pre>
            </div>
        </body>
        </html>
        """
        
        # Prepare template data
        template_data = {
            'report_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities_found': dashboard['executive_summary']['vulnerabilities_discovered'],
            'risk_score': dashboard['executive_summary']['overall_risk_score'],
            'total_tests': dashboard['executive_summary']['total_tests_performed'],
            'scan_duration': dashboard['executive_summary']['scan_duration_minutes'],
            'findings': self._format_findings_for_html(technical_report),
            'recommendations': dashboard['recommendations'],
            'attack_vector_chart': visualizations.get('attack_vectors', ''),
            'risk_heatmap': visualizations.get('risk_heatmap', ''),
            'technical_details': json.dumps(technical_report, indent=2)
        }
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def export_to_json(self, dashboard: Dict[str, Any], technical_report: Dict[str, Any],
                      forensic_report: Dict[str, Any], output_file: str = 'security_report.json'):
        """Export comprehensive report to JSON"""
        
        complete_report = {
            'metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'scan_type': 'comprehensive_sql_injection'
            },
            'executive_dashboard': dashboard,
            'technical_analysis': technical_report,
            'forensic_analysis': forensic_report,
            'evidence_chain': [asdict(evidence) for evidence in self.evidence_chain]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(complete_report, f, indent=2, default=str)
        
        return output_file
    
    def _calculate_overall_risk_score(self, results: List[TestResult],
                                    multi_vector_results: List[MultiVectorResult],
                                    ai_predictions: List[PredictionResult]) -> float:
        """Calculate overall risk score (0-10)"""
        
        # Base score from vulnerabilities
        sql_vulns = len([r for r in results if r.vulnerable])
        multi_vulns = len([r for r in multi_vector_results if r.success])
        
        base_score = min(8.0, (sql_vulns + multi_vulns) * 0.5)
        
        # AI confidence factor
        if ai_predictions:
            avg_ai_confidence = sum(p.confidence_score for p in ai_predictions) / len(ai_predictions)
            ai_factor = avg_ai_confidence * 2.0
        else:
            ai_factor = 0.0
        
        # Critical findings multiplier
        critical_findings = len([r for r in multi_vector_results if r.impact_level == 'CRITICAL'])
        critical_multiplier = 1.0 + (critical_findings * 0.2)
        
        total_score = min(10.0, (base_score + ai_factor) * critical_multiplier)
        
        return round(total_score, 1)
    
    def _determine_security_posture(self, risk_score: float) -> str:
        """Determine security posture based on risk score"""
        if risk_score >= 8.0:
            return "CRITICAL - Immediate Action Required"
        elif risk_score >= 6.0:
            return "HIGH RISK - Urgent Remediation Needed"
        elif risk_score >= 4.0:
            return "MEDIUM RISK - Remediation Recommended"
        elif risk_score >= 2.0:
            return "LOW RISK - Monitor and Improve"
        else:
            return "MINIMAL RISK - Good Security Posture"
    
    def _generate_risk_breakdown(self, results: List[TestResult],
                               multi_vector_results: List[MultiVectorResult]) -> Dict[str, Any]:
        """Generate detailed risk breakdown"""
        
        risk_categories = {
            'sql_injection': len([r for r in results if r.vulnerable]),
            'header_injection': len([r for r in multi_vector_results if r.vector_type == 'HTTP Header Injection' and r.success]),
            'cookie_injection': len([r for r in multi_vector_results if r.vector_type == 'Cookie SQL Injection' and r.success]),
            'file_upload': len([r for r in multi_vector_results if r.vector_type == 'File Upload Injection' and r.success]),
            'xml_pollution': len([r for r in multi_vector_results if r.vector_type == 'XML Parameter Pollution' and r.success]),
            'json_pollution': len([r for r in multi_vector_results if r.vector_type == 'JSON Parameter Pollution' and r.success]),
            'websocket_injection': len([r for r in multi_vector_results if r.vector_type == 'WebSocket Injection' and r.success]),
            'api_pollution': len([r for r in multi_vector_results if r.vector_type == 'API Parameter Pollution' and r.success]),
            'graphql_injection': len([r for r in multi_vector_results if r.vector_type == 'GraphQL Injection' and r.success])
        }
        
        return risk_categories
    
    def _analyze_attack_vectors(self, multi_vector_results: List[MultiVectorResult]) -> Dict[str, Any]:
        """Analyze attack vector effectiveness"""
        
        vector_analysis = {}
        
        for result in multi_vector_results:
            vector_type = result.vector_type
            if vector_type not in vector_analysis:
                vector_analysis[vector_type] = {
                    'total_attempts': 0,
                    'successful_attacks': 0,
                    'average_confidence': 0.0,
                    'impact_levels': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                }
            
            analysis = vector_analysis[vector_type]
            analysis['total_attempts'] += 1
            
            if result.success:
                analysis['successful_attacks'] += 1
            
            analysis['impact_levels'][result.impact_level] += 1
        
        # Calculate averages
        for vector_type, analysis in vector_analysis.items():
            vector_results = [r for r in multi_vector_results if r.vector_type == vector_type]
            if vector_results:
                analysis['average_confidence'] = sum(r.confidence for r in vector_results) / len(vector_results)
                analysis['success_rate'] = (analysis['successful_attacks'] / analysis['total_attempts']) * 100
        
        return vector_analysis
    
    def _extract_ai_insights(self, ai_predictions: List[PredictionResult]) -> Dict[str, Any]:
        """Extract insights from AI analysis"""
        
        if not ai_predictions:
            return {'status': 'No AI predictions available'}
        
        insights = {
            'total_predictions': len(ai_predictions),
            'average_vulnerability_probability': sum(p.vulnerability_probability for p in ai_predictions) / len(ai_predictions),
            'average_confidence': sum(p.confidence_score for p in ai_predictions) / len(ai_predictions),
            'attack_vectors_predicted': list(set(p.attack_vector for p in ai_predictions)),
            'high_confidence_predictions': len([p for p in ai_predictions if p.confidence_score > 0.8]),
            'ai_recommended_payloads': []
        }
        
        # Collect unique recommended payloads
        all_payloads = []
        for prediction in ai_predictions:
            all_payloads.extend(prediction.recommended_payloads)
        
        insights['ai_recommended_payloads'] = list(set(all_payloads))[:10]  # Top 10 unique payloads
        
        return insights
    
    async def _assess_compliance_status(self, results: List[TestResult],
                                      multi_vector_results: List[MultiVectorResult]) -> Dict[str, str]:
        """Assess compliance with various standards"""
        
        vulnerabilities_found = len([r for r in results if r.vulnerable]) + \
                              len([r for r in multi_vector_results if r.success])
        
        compliance_status = {}
        
        # OWASP Top 10
        if vulnerabilities_found == 0:
            compliance_status['OWASP_A03_2021'] = 'COMPLIANT'
        else:
            compliance_status['OWASP_A03_2021'] = 'NON-COMPLIANT'
        
        # PCI DSS
        if vulnerabilities_found == 0:
            compliance_status['PCI_DSS_6.2'] = 'COMPLIANT'
        else:
            compliance_status['PCI_DSS_6.2'] = 'NON-COMPLIANT'
        
        # NIST
        compliance_status['NIST_800_53'] = 'REQUIRES_REVIEW' if vulnerabilities_found > 0 else 'COMPLIANT'
        
        return compliance_status
    
    def _generate_executive_recommendations(self, results: List[TestResult],
                                          multi_vector_results: List[MultiVectorResult]) -> List[str]:
        """Generate executive-level recommendations"""
        
        recommendations = []
        
        sql_vulns = len([r for r in results if r.vulnerable])
        multi_vulns = len([r for r in multi_vector_results if r.success])
        
        if sql_vulns > 0:
            recommendations.append("Immediately implement parameterized queries and input validation")
        
        if multi_vulns > 0:
            recommendations.append("Deploy Web Application Firewall (WAF) with SQL injection protection")
        
        critical_findings = len([r for r in multi_vector_results if r.impact_level == 'CRITICAL'])
        if critical_findings > 0:
            recommendations.append("Address critical vulnerabilities within 24-48 hours")
        
        recommendations.extend([
            "Conduct regular security code reviews",
            "Implement security training for development teams",
            "Establish continuous security testing in CI/CD pipeline",
            "Consider bug bounty program for ongoing security validation"
        ])
        
        return recommendations
    
    def _generate_trend_analysis(self) -> Dict[str, Any]:
        """Generate security trend analysis"""
        
        # This would typically analyze historical data
        # For now, return basic trend information
        
        return {
            'scan_frequency': 'First scan - no historical data',
            'vulnerability_trend': 'Baseline established',
            'risk_trend': 'Initial assessment completed',
            'recommendations': [
                'Establish regular scanning schedule',
                'Track vulnerability remediation metrics',
                'Monitor security posture improvements'
            ]
        }
    
    def _calculate_cost_impact(self, vulnerabilities_found: int, risk_score: float) -> Dict[str, Any]:
        """Calculate potential cost impact of vulnerabilities"""
        
        # Industry average costs (in USD)
        base_breach_cost = 4.45e6  # $4.45M average data breach cost
        vuln_factor = min(1.0, vulnerabilities_found / 10.0)
        risk_multiplier = risk_score / 10.0
        
        potential_cost = base_breach_cost * vuln_factor * risk_multiplier
        
        return {
            'potential_breach_cost': f"${potential_cost:,.0f}",
            'remediation_cost_estimate': f"${potential_cost * 0.1:,.0f}",  # 10% of potential breach cost
            'roi_of_remediation': f"{900}%",  # 9:1 ROI typical for security investments
            'business_impact': 'HIGH' if risk_score > 6 else 'MEDIUM' if risk_score > 3 else 'LOW'
        }
    
    def _analyze_sql_findings(self, results: List[TestResult]) -> Dict[str, Any]:
        """Analyze SQL injection findings"""
        
        vulnerable_results = [r for r in results if r.vulnerable]
        
        analysis = {
            'total_sql_tests': len(results),
            'successful_injections': len(vulnerable_results),
            'success_rate': (len(vulnerable_results) / len(results)) * 100 if results else 0,
            'injection_types': {},
            'database_types_detected': [],
            'payload_analysis': {}
        }
        
        # Analyze injection types and payloads
        for result in vulnerable_results:
            # This would typically categorize injection types
            # For now, use basic categorization
            analysis['injection_types']['classic'] = analysis['injection_types'].get('classic', 0) + 1
        
        return analysis
    
    def _analyze_multi_vector_findings(self, multi_vector_results: List[MultiVectorResult]) -> Dict[str, Any]:
        """Analyze multi-vector attack findings"""
        
        successful_results = [r for r in multi_vector_results if r.success]
        
        analysis = {
            'total_multi_vector_tests': len(multi_vector_results),
            'successful_attacks': len(successful_results),
            'success_rate': (len(successful_results) / len(multi_vector_results)) * 100 if multi_vector_results else 0,
            'attack_vector_breakdown': {},
            'impact_distribution': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'confidence_statistics': {}
        }
        
        # Analyze by vector type
        for result in multi_vector_results:
            vector_type = result.vector_type
            analysis['attack_vector_breakdown'][vector_type] = analysis['attack_vector_breakdown'].get(vector_type, 0) + 1
            analysis['impact_distribution'][result.impact_level] += 1
        
        # Calculate confidence statistics
        if multi_vector_results:
            confidences = [r.confidence for r in multi_vector_results]
            analysis['confidence_statistics'] = {
                'mean': statistics.mean(confidences),
                'median': statistics.median(confidences),
                'std_dev': statistics.stdev(confidences) if len(confidences) > 1 else 0,
                'max': max(confidences),
                'min': min(confidences)
            }
        
        return analysis
    
    def _analyze_ai_predictions(self, ai_predictions: List[PredictionResult]) -> Dict[str, Any]:
        """Analyze AI prediction results"""
        
        if not ai_predictions:
            return {'status': 'No AI predictions to analyze'}
        
        analysis = {
            'total_predictions': len(ai_predictions),
            'prediction_statistics': {},
            'feature_importance_summary': {},
            'model_performance': {}
        }
        
        # Calculate prediction statistics
        vuln_probs = [p.vulnerability_probability for p in ai_predictions]
        confidences = [p.confidence_score for p in ai_predictions]
        
        analysis['prediction_statistics'] = {
            'vulnerability_probability': {
                'mean': statistics.mean(vuln_probs),
                'median': statistics.median(vuln_probs),
                'std_dev': statistics.stdev(vuln_probs) if len(vuln_probs) > 1 else 0
            },
            'confidence_scores': {
                'mean': statistics.mean(confidences),
                'median': statistics.median(confidences),
                'std_dev': statistics.stdev(confidences) if len(confidences) > 1 else 0
            }
        }
        
        return analysis
    
    async def _analyze_attack_surface(self, results: List[TestResult],
                                    multi_vector_results: List[MultiVectorResult]) -> Dict[str, Any]:
        """Analyze the application's attack surface"""
        
        # Collect all injection points
        injection_points = set()
        
        for result in results:
            injection_points.add(f"{result.injection_point.method}:{result.injection_point.name}")
        
        for result in multi_vector_results:
            injection_points.add(f"{result.vector_type}:{result.injection_point}")
        
        attack_surface = {
            'total_injection_points': len(injection_points),
            'vulnerable_points': len([r for r in results if r.vulnerable]) + 
                               len([r for r in multi_vector_results if r.success]),
            'attack_vectors_present': len(set(r.vector_type for r in multi_vector_results)),
            'coverage_analysis': {
                'parameters_tested': len(set(r.injection_point.name for r in results)),
                'vectors_tested': len(set(r.vector_type for r in multi_vector_results)),
                'methods_tested': len(set(r.injection_point.method for r in results))
            }
        }
        
        return attack_surface
    
    def _create_risk_heatmap(self, results: List[TestResult],
                           multi_vector_results: List[MultiVectorResult]) -> str:
        """Create risk assessment heatmap"""
        
        try:
            # Prepare data for heatmap
            risk_data = []
            
            # Process SQL injection results
            for result in results:
                if result.vulnerable:
                    risk_data.append({
                        'category': 'SQL Injection',
                        'parameter': result.injection_point.name,
                        'risk_level': 8 if result.confidence > 0.8 else 6 if result.confidence > 0.5 else 4
                    })
            
            # Process multi-vector results
            for result in multi_vector_results:
                if result.success:
                    risk_levels = {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 6, 'LOW': 4}
                    risk_data.append({
                        'category': result.vector_type,
                        'parameter': result.injection_point,
                        'risk_level': risk_levels.get(result.impact_level, 4)
                    })
            
            if not risk_data:
                return "No vulnerabilities found for heatmap generation"
            
            # Create DataFrame
            df = pd.DataFrame(risk_data)
            
            # Create pivot table for heatmap
            heatmap_data = df.pivot_table(values='risk_level', index='category', 
                                        columns='parameter', fill_value=0)
            
            # Create heatmap
            plt.figure(figsize=(12, 8))
            sns.heatmap(heatmap_data, annot=True, cmap='Reds', cbar_kws={'label': 'Risk Level'})
            plt.title('Security Risk Heatmap')
            plt.tight_layout()
            
            # Save to base64 string
            import io
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png')
            img_buffer.seek(0)
            img_str = base64.b64encode(img_buffer.getvalue()).decode()
            plt.close()
            
            return f'<img src="data:image/png;base64,{img_str}" alt="Risk Heatmap">'
            
        except Exception as e:
            return f"Error generating heatmap: {str(e)}"
    
    def _create_attack_vector_chart(self, multi_vector_results: List[MultiVectorResult]) -> str:
        """Create attack vector distribution chart"""
        
        try:
            # Count attack vectors
            vector_counts = {}
            for result in multi_vector_results:
                vector_counts[result.vector_type] = vector_counts.get(result.vector_type, 0) + 1
            
            if not vector_counts:
                return "No attack vector data available"
            
            # Create pie chart
            plt.figure(figsize=(10, 8))
            plt.pie(vector_counts.values(), labels=vector_counts.keys(), autopct='%1.1f%%')
            plt.title('Attack Vector Distribution')
            
            # Save to base64 string
            import io
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png')
            img_buffer.seek(0)
            img_str = base64.b64encode(img_buffer.getvalue()).decode()
            plt.close()
            
            return f'<img src="data:image/png;base64,{img_str}" alt="Attack Vector Chart">'
            
        except Exception as e:
            return f"Error generating attack vector chart: {str(e)}"
    
    async def _generate_owasp_report(self, results: List[TestResult],
                                   multi_vector_results: List[MultiVectorResult]) -> ComplianceReport:
        """Generate OWASP compliance report"""
        
        findings = []
        risk_score = 0.0
        
        # Check A03:2021 - Injection
        sql_vulns = len([r for r in results if r.vulnerable])
        if sql_vulns > 0:
            findings.append({
                'control': 'A03:2021 - Injection',
                'status': 'FAIL',
                'description': f'{sql_vulns} SQL injection vulnerabilities found',
                'recommendation': 'Implement parameterized queries and input validation'
            })
            risk_score += 3.0
        
        # Additional OWASP checks based on multi-vector results
        for result in multi_vector_results:
            if result.success and result.impact_level in ['CRITICAL', 'HIGH']:
                risk_score += 1.0
        
        compliance_status = 'NON-COMPLIANT' if risk_score > 0 else 'COMPLIANT'
        
        return ComplianceReport(
            standard='OWASP Top 10 2021',
            findings=findings,
            risk_score=min(10.0, risk_score),
            compliance_status=compliance_status,
            recommendations=['Implement secure coding practices', 'Regular security testing', 'Security training']
        )
    
    # Additional methods would be implemented for other compliance standards...
    # (PCI-DSS, GDPR, SOX, etc.)
    
    def _format_findings_for_html(self, technical_report: Dict[str, Any]) -> List[Dict[str, str]]:
        """Format findings for HTML template"""
        
        findings = []
        
        # Add SQL injection findings
        sql_analysis = technical_report.get('vulnerability_analysis', {}).get('sql_injection_findings', {})
        if sql_analysis.get('successful_injections', 0) > 0:
            findings.append({
                'type': 'SQL Injection',
                'severity': 'HIGH',
                'confidence': '85',
                'impact': 'Data breach potential',
                'remediation': 'Use parameterized queries'
            })
        
        # Add multi-vector findings
        multi_analysis = technical_report.get('vulnerability_analysis', {}).get('multi_vector_findings', {})
        if multi_analysis.get('successful_attacks', 0) > 0:
            findings.append({
                'type': 'Multi-Vector Attack',
                'severity': 'HIGH',
                'confidence': '75',
                'impact': 'Multiple attack surfaces',
                'remediation': 'Comprehensive input validation'
            })
        
        return findings
    
    # Additional helper methods for timeline, forensics, etc. would be implemented here...