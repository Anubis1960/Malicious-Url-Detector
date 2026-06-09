from datetime import datetime
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

    # Check for suspicious keywords in URL
    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update',
                           'confirm', 'signin', 'banking', 'paypal', 'apple',
                           'microsoft', 'amazon', 'google', 'security']

    url_lower = url.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
    if found_keywords:
        issues.append(f"Suspicious keywords detected: {', '.join(found_keywords[:3])}")
        score_deduction += 10

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

        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age_days = (datetime.now() - creation_date).days

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
                'score_deduction': 8,
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


def generate_detailed_report(url, analysis_results):
    """Generate comprehensive HTML/JSON report"""
    report = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'final_score': analysis_results['final_score'],
        'severity': analysis_results['severity'],
        'risk_level': analysis_results['risk_level'],
        'summary': analysis_results['summary'],
        'detailed_findings': {}
    }

    # Add each component's findings
    for component, results in analysis_results.items():
        if component not in ['final_score', 'severity', 'risk_level', 'summary']:
            report['detailed_findings'][component] = results

    # Generate recommendations
    recommendations = []
    if analysis_results.get('url_structure', {}).get('issues'):
        recommendations.append("Review URL structure - contains suspicious patterns")
    if analysis_results.get('homoglyphs', {}).get('has_homoglyphs'):
        recommendations.append("Domain contains homoglyph characters - potential spoofing attempt")
    if analysis_results.get('virustotal', {}).get('malicious_count', 0) > 0:
        recommendations.append(
            f"VirusTotal detected {analysis_results['virustotal']['malicious_count']} malicious engines - avoid this URL")
    if analysis_results.get('domain_age', {}).get('age_days', 0) < 30:
        recommendations.append("Domain is very new - exercise caution")
    if not analysis_results.get('ssl_tls', {}).get('has_ssl', False):
        recommendations.append("No valid SSL certificate - data transmission not secure")

    report['recommendations'] = recommendations

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
        summary_parts.append(f"⚡ VirusTotal: {vt['suspicious_count']} vendors found suspicious activity")
    else:
        summary_parts.append("✅ VirusTotal: No security vendors flagged this URL")

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
        summary_parts.append("🔒 No valid SSL certificate found (security risk)")

    # Homoglyphs
    if scores['homoglyphs']['has_homoglyphs']:
        summary_parts.append("Homoglyph characters detected - possible domain spoofing")

    return " | ".join(summary_parts)


class URLSecurityAnalyzer:
    def __init__(self):
        self.score_weights = {
            'virustotal': 35,
            'ml_prediction': 25,
            'homoglyphs': 15,
            'url_structure': 10,
            'domain_age': 5,
            'ssl_tls': 5,
            'blacklists': 5
        }
        self.max_score = 100

    def calculate_final_score(self, scores):
        """Calculate weighted final score"""
        weighted_score = 100

        # VirusTotal contribution (weighted)
        vt_deduction = scores.get('virustotal', {}).get('score_deduction', 0)
        weighted_score -= (vt_deduction * self.score_weights['virustotal'] / 100)

        # ML Prediction contribution
        ml_deduction = scores.get('ml_prediction', {}).get('score_deduction', 0)
        weighted_score -= (ml_deduction * self.score_weights['ml_prediction'] / 100)

        # Homoglyph contribution
        homo_deduction = scores.get('homoglyphs', {}).get('score_deduction', 0)
        weighted_score -= (homo_deduction * self.score_weights['homoglyphs'] / 100)

        # URL structure contribution
        structure_deduction = scores.get('url_structure', {}).get('score_deduction', 0)
        weighted_score -= (structure_deduction * self.score_weights['url_structure'] / 100)

        # Domain age contribution
        age_deduction = scores.get('domain_age', {}).get('score_deduction', 0)
        weighted_score -= (age_deduction * self.score_weights['domain_age'] / 100)

        # SSL/TLS contribution
        ssl_deduction = scores.get('ssl_tls', {}).get('score_deduction', 0)
        weighted_score -= (ssl_deduction * self.score_weights['ssl_tls'] / 100)

        return max(0, min(100, weighted_score))

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

        # Calculate final weighted score
        final_score = self.calculate_final_score(scores)
        severity, risk_level = get_severity_level(final_score)

        # Generate summary
        summary = generate_summary(scores, final_score, severity)

        # Compile all results
        results = {
            **scores,
            'final_score': round(final_score, 1),
            'severity': severity,
            'risk_level': risk_level,
            'summary': summary
        }

        # Generate detailed report
        detailed_report = generate_detailed_report(url, results)

        return detailed_report


def analyze(url):
    """Legacy function for backward compatibility"""
    analyzer = URLSecurityAnalyzer()
    report = analyzer.analyze(url)

    # Print comprehensive report
    print("\n" + "=" * 80)
    print(f"URL SECURITY ANALYSIS REPORT")
    print("=" * 80)
    print(f"URL: {report['url']}")
    print(f"Timestamp: {report['timestamp']}")
    print(f"\nFINAL SCORE: {report['final_score']}/100")
    print(f"RISK LEVEL: {report['risk_level']}")
    print(f"SEVERITY: {report['severity']}")
    print(f"\nSUMMARY: {report['summary']}")

    print("\n" + "-" * 40)
    print("DETAILED FINDINGS:")
    print("-" * 40)

    for category, findings in report['detailed_findings'].items():
        print(f"\n{category.upper().replace('_', ' ')}:")
        if isinstance(findings, dict):
            for key, value in findings.items():
                if value and key not in ['issues']:
                    print(f"  • {key.replace('_', ' ').title()}: {value}")
            if 'issues' in findings and findings['issues']:
                print("  • Issues detected:")
                for issue in findings['issues'][:3]:  # Show top 3 issues
                    print(f"    - {issue}")

    if report['recommendations']:
        print("\n" + "-" * 40)
        print("RECOMMENDATIONS:")
        print("-" * 40)
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"{i}. {rec}")

    print("\n" + "=" * 80)

    return report['final_score']



