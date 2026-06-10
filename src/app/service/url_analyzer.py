from datetime import datetime, timezone
import re
import socket
import ssl
from urllib.parse import urlparse
import tldextract
import whois
from src.infra.virustotal.virustotal import run_virustotal_check
from src.infra.model.predict import predict_url
from src.app.service.util.homoglyph import detect_homoglyphs


def analyze_url_structure(url):
    """Analyze URL structure for suspicious patterns"""
    parsed = urlparse(url)
    issues = []
    score_deduction = 0

    # Check for IP address instead of domain
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc.split(':')[0]):
        issues.append("URL uses IP address instead of domain name")
        score_deduction += 15

    # Check for excessive subdomains
    subdomain_count = parsed.netloc.count('.') - 1
    if subdomain_count > 3:
        issues.append(f"Excessive subdomains ({subdomain_count})")
        score_deduction += 10
    elif subdomain_count > 2:
        issues.append(f"Many subdomains ({subdomain_count})")
        score_deduction += 5

    # Check for excessive URL length
    if len(url) > 100:
        issues.append(f"Unusually long URL ({len(url)} characters)")
        score_deduction += 8
    elif len(url) > 75:
        issues.append(f"Long URL ({len(url)} characters)")
        score_deduction += 4

    # Check for multiple redirects or URL encoding
    if '%' in url or '//' in url[8:]:
        issues.append("URL contains encoded characters or multiple slashes")
        score_deduction += 5

    # Check for port usage (non-standard ports)
    if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443'):
        port = parsed.netloc.split(':')[-1]
        issues.append(f"Non-standard port usage: {port}")
        score_deduction += 8

    return {
        'score_deduction': min(score_deduction, 30),
        'issues': issues,
        'structure_safe': score_deduction < 10,
        'subdomain_count': subdomain_count,
        'url_length': len(url),
        'has_ip_address': bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc.split(':')[0]))
    }


def check_domain_age(url):
    """Check domain age using WHOIS"""
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        domain_info = whois.whois(domain)

        if domain_info['creation_date']:
            creation_date = domain_info['creation_date']

            age_days = (datetime.now(timezone.utc) - creation_date).days

            if age_days < 30:
                return {
                    'score_deduction': 15,
                    'age_days': age_days,
                    'assessment': 'Very new domain (high risk)',
                    'creation_date': creation_date.strftime('%Y-%m-%d')
                }
            elif age_days < 180:
                return {
                    'score_deduction': 8,
                    'age_days': age_days,
                    'assessment': 'Recently created domain (moderate risk)',
                    'creation_date': creation_date.strftime('%Y-%m-%d')
                }
            else:
                return {
                    'score_deduction': 0,
                    'age_days': age_days,
                    'assessment': 'Established domain (low risk)',
                    'creation_date': creation_date.strftime('%Y-%m-%d')
                }
    except Exception as e:
        return {
            'score_deduction': 5,
            'error': f"WHOIS lookup failed: {str(e)}",
            'assessment': 'Unable to verify domain age'
        }


def check_ssl_tls(url):
    """Check SSL/TLS certificate validity"""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Check certificate validity
        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (expiry_date - datetime.now()).days

        # Check for organization validation
        has_org = 'organizationName' in str(cert.get('subject', []))

        if days_until_expiry < 0:
            return {
                'score_deduction': 15,
                'has_ssl': True,
                'valid': False,
                'assessment': 'Expired SSL certificate',
                'expiry_days': days_until_expiry
            }
        elif days_until_expiry < 30:
            return {
                'score_deduction': 5,
                'has_ssl': True,
                'valid': True,
                'assessment': 'SSL certificate expiring soon',
                'expiry_days': days_until_expiry
            }
        elif has_org:
            return {
                'score_deduction': 0,
                'has_ssl': True,
                'valid': True,
                'assessment': 'Valid SSL certificate with organization validation',
                'expiry_days': days_until_expiry
            }
        else:
            return {
                'score_deduction': 3,
                'has_ssl': True,
                'valid': True,
                'assessment': 'Valid SSL certificate (domain validation only)',
                'expiry_days': days_until_expiry
            }

    except socket.timeout:
        return {
            'score_deduction': 10,
            'has_ssl': False,
            'assessment': 'SSL check timeout (potential connection issue)'
        }
    except Exception as e:
        return {
            'score_deduction': 10,
            'has_ssl': False,
            'assessment': 'SSL check timeout (potential connection issue)'
        }


def get_severity_level(score):
    """Get severity level based on final score"""
    if score >= 80:
        return "LOW RISK", "Safe"
    elif score >= 60:
        return "LOW-MEDIUM RISK", "Potentially Safe"
    elif score >= 40:
        return "MEDIUM RISK", "Suspicious"
    elif score >= 20:
        return "HIGH RISK", "Dangerous"
    else:
        return "CRITICAL RISK", "Very Dangerous"


def generate_report(url, analysis_results):
    report = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'final_score': analysis_results['final_score'],
        'severity': analysis_results['severity'],
        'risk_level': analysis_results['risk_level'],
        'summary': analysis_results['summary'],
        'detailed_findings': {},
        'component_scores': analysis_results.get('component_scores', {})
    }

    # Add each component's findings
    for component, results in analysis_results.items():
        if component not in ['final_score', 'severity', 'risk_level', 'summary', 'component_scores']:
            report['detailed_findings'][component] = results

    return report


def generate_summary(scores, final_score, severity):
    """Generate human-readable summary"""
    summary_parts = [f"URL Analysis Complete: {severity} (Score: {final_score:.1f}/100)"]

    # VirusTotal findings
    vt = scores['virustotal']
    if vt['malicious_count'] > 0:
        summary_parts.append(
            f"VirusTotal: {vt['malicious_count']} security vendors flagged this URL as malicious")
    elif vt['suspicious_count'] > 0:
        summary_parts.append(f"VirusTotal: {vt['suspicious_count']} vendors found suspicious activity")
    else:
        summary_parts.append("VirusTotal: No security vendors flagged this URL")

    # ML findings
    ml = scores['ml_prediction']
    if ml['prediction'] != 'benign':
        summary_parts.append(
            f"ML Detection: Classified as {ml['prediction'].upper()} (confidence: {ml['confidence']:.1%})")
    else:
        summary_parts.append("ML Detection: Classified as BENIGN")

    # Structure findings
    structure = scores['url_structure']
    if structure['has_ip_address']:
        summary_parts.append("🌐 URL uses IP address instead of domain name (suspicious)")
    elif structure['subdomain_count'] > 2:
        summary_parts.append(f"📊 URL has {structure['subdomain_count']} subdomains (unusual)")

    # Domain age
    age = scores['domain_age']
    if 'age_days' in age:
        if age['age_days'] < 30:
            summary_parts.append(f"Domain is very young ({age['age_days']} days old)")
        elif age['age_days'] < 180:
            summary_parts.append(f"Domain is relatively new ({age['age_days']} days old)")

    # SSL/TLS
    ssl = scores['ssl_tls']
    if not ssl.get('has_ssl', False):
        summary_parts.append("No valid SSL certificate found (security risk)")

    # Homoglyphs
    if scores['homoglyphs']['has_homoglyphs']:
        summary_parts.append("Homoglyph characters detected - possible domain spoofing")

    return " | ".join(summary_parts)


class URLSecurityAnalyzer:
    def __init__(self):
        """
        Weights define how much each component affects the final score (as percentages).
        Higher weight = more impact on final score.
        """
        self.score_weights = {
            'virustotal': 35,  # Reputation data is most important
            'ml_prediction': 25,  # ML model detection
            'homoglyphs': 15,  # Domain spoofing detection
            'url_structure': 10,  # Structural red flags
            'ssl_tls': 8,  # Certificate validation
            'domain_age': 5,  # Domain age (least important)
            'blacklists': 2  # Blacklist checks (reserved for future use)
        }

        # Verify weights sum to 100
        total_weight = sum(self.score_weights.values())
        if total_weight != 100:
            raise ValueError(f"Score weights must sum to 100, got {total_weight}")

    def _normalize_to_score(self, deduction, max_deduction):
        """
        Convert a deduction value (0 to max_deduction) into a 0-100 score.
        Score of 100 = safe/benign, Score of 0 = most dangerous
        """
        if max_deduction <= 0:
            return 100
        # Deduction as percentage, then convert to safety score
        percentage_deduction = min(deduction, max_deduction) / max_deduction
        return 100 - (percentage_deduction * 100)

    def calculate_final_score(self, scores):
        """
        Calculate weighted final score using normalized component scores.

        Process:
        1. Normalize each component to 0-100 scale
        2. Apply weight to each component
        3. Sum weighted scores for final result
        """
        component_scores = {}
        weighted_sum = 0

        # VirusTotal (max deduction: 40)
        vt_deduction = scores.get('virustotal', {}).get('score_deduction', 0)
        vt_score = self._normalize_to_score(vt_deduction, 40)
        component_scores['virustotal'] = vt_score
        weighted_sum += vt_score * (self.score_weights['virustotal'] / 100)

        # ML Prediction (max deduction: 30)
        ml_deduction = scores.get('ml_prediction', {}).get('score_deduction', 0)
        ml_score = self._normalize_to_score(ml_deduction, 30)
        component_scores['ml_prediction'] = ml_score
        weighted_sum += ml_score * (self.score_weights['ml_prediction'] / 100)

        # Homoglyphs (max deduction: 15)
        homo_deduction = scores.get('homoglyphs', {}).get('score_deduction', 0)
        homo_score = self._normalize_to_score(homo_deduction, 15)
        component_scores['homoglyphs'] = homo_score
        weighted_sum += homo_score * (self.score_weights['homoglyphs'] / 100)

        # URL Structure (max deduction: 30)
        structure_deduction = scores.get('url_structure', {}).get('score_deduction', 0)
        structure_score = self._normalize_to_score(structure_deduction, 30)
        component_scores['url_structure'] = structure_score
        weighted_sum += structure_score * (self.score_weights['url_structure'] / 100)

        # Domain Age (max deduction: 15)
        age_deduction = scores.get('domain_age', {}).get('score_deduction', 0)
        age_score = self._normalize_to_score(age_deduction, 15)
        component_scores['domain_age'] = age_score
        weighted_sum += age_score * (self.score_weights['domain_age'] / 100)

        # SSL/TLS (max deduction: 15)
        ssl_deduction = scores.get('ssl_tls', {}).get('score_deduction', 0)
        ssl_score = self._normalize_to_score(ssl_deduction, 15)
        component_scores['ssl_tls'] = ssl_score
        weighted_sum += ssl_score * (self.score_weights['ssl_tls'] / 100)

        return max(0, min(100, weighted_sum)), component_scores

    def analyze(self, url):
        """Main analysis function with comprehensive reporting"""

        # Perform all checks
        virustotal = run_virustotal_check(url)
        url_prediction = predict_url(url)
        homoglyphs = detect_homoglyphs(url)
        url_structure = analyze_url_structure(url)
        domain_age = check_domain_age(url)
        ssl_tls = check_ssl_tls(url)

        # Calculate scores for each component
        if virustotal.get('verdict') == 'malicious':
            vt_score = 40
        elif virustotal.get('verdict') == 'suspicious':
            vt_score = 25
        elif virustotal.get('verdict') == 'clean':
            vt_score = 0
        else:
            vt_score = 10  # Error or unknown

        ml_score = 0
        ml_pred = url_prediction.get('ensemble_prediction', 'benign')
        if ml_pred != 'benign':
            ml_score = 30 if ml_pred == 'malware' else 20

        homo_score = 15 if homoglyphs.get('has_homoglyphs') else 0

        # Collect all scores
        scores = {
            'virustotal': {
                'score_deduction': vt_score,
                'verdict': virustotal.get('verdict'),
                'malicious_count': virustotal.get('malicious', 0),
                'suspicious_count': virustotal.get('suspicious', 0),
                'total_engines': virustotal.get('total_engines', 0)
            },
            'ml_prediction': {
                'score_deduction': ml_score,
                'prediction': ml_pred,
                'confidence': url_prediction.get('ensemble_confidence', 0),
                'individual_predictions': url_prediction.get('individual_predictions', {})
            },
            'homoglyphs': {
                'score_deduction': homo_score,
                'has_homoglyphs': homoglyphs.get('has_homoglyphs', False),
                'suspicious_chars': homoglyphs.get('suspicious_characters', []),
                'original_domain': homoglyphs.get('original_domain', ''),
                'normalized_domain': homoglyphs.get('normalized_domain', '')
            },
            'url_structure': url_structure,
            'domain_age': domain_age,
            'ssl_tls': ssl_tls
        }

        # Calculate final weighted score with component breakdown
        final_score, component_scores = self.calculate_final_score(scores)
        severity, risk_level = get_severity_level(final_score)

        # Generate summary
        summary = generate_summary(scores, final_score, severity)

        # Compile all results
        results = {
            **scores,
            'final_score': round(final_score, 1),
            'severity': severity,
            'risk_level': risk_level,
            'summary': summary,
            'component_scores': component_scores
        }

        # Generate detailed report
        detailed_report = generate_report(url, results)

        return detailed_report


def analyze(url):
    """Legacy function for backward compatibility"""
    analyzer = URLSecurityAnalyzer()
    report = analyzer.analyze(url)

    # Print comprehensive report
    print(f"URL SECURITY ANALYSIS REPORT")
    print("\n")
    print(f"URL: {report['url']}")
    print(f"Timestamp: {report['timestamp']}")
    print(f"\nFINAL SCORE: {report['final_score']}/100")
    print(f"RISK LEVEL: {report['risk_level']}")
    print(f"SEVERITY: {report['severity']}")
    print(f"\nSUMMARY: {report['summary']}")

    # Print component scores
    print(f"\nCOMPONENT TRUST SCORES (weighted):")
    for component, score in report.get('component_scores', {}).items():
        print(f"  {component.replace('_', ' ').title()}: {score:.1f}/100")

    print("\n")
    print("DETAILED FINDINGS:")
    print("\n")

    for category, findings in report['detailed_findings'].items():
        print(f"\n{category.upper().replace('_', ' ')}:")
        if isinstance(findings, dict):
            for key, value in findings.items():
                if value and key not in ['issues']:
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            if 'issues' in findings and findings['issues']:
                print("  Issues detected:")
                for issue in findings['issues'][:3]:  # Show top 3 issues
                    print(f"    {issue}")

    return report['final_score']