import os
import time
import json
import asyncio
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Any, Optional
import base64

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# For screenshot and network capture
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def save_screenshots(analysis_result: Dict[str, Any], output_dir: str = "screenshots"):
    """Save captured screenshots to disk"""
    if 'screenshots' not in analysis_result:
        return

    os.makedirs(output_dir, exist_ok=True)

    if 'full_page' in analysis_result['screenshots']:
        screenshot_data = analysis_result['screenshots']['full_page']
        filename = f"{output_dir}/{datetime.now().strftime('%Y%m%d_%H%M%S')}_fullpage.png"

        with open(filename, 'wb') as f:
            f.write(base64.b64decode(screenshot_data))

        logger.info(f"Screenshot saved to {filename}")
        return filename

    return None


def generate_report(analysis_result: Dict[str, Any]) -> str:
    """Generate a human-readable report from analysis results"""
    report = []
    report.append("HEADLESS BROWSER SECURITY ANALYSIS REPORT")
    report.append(f"Timestamp: {analysis_result.get('timestamp', 'N/A')}")

    if 'error' in analysis_result:
        report.append(f"\n❌ ERROR: {analysis_result['error']}")
        return "\n".join(report)

    # Page Information
    page_info = analysis_result.get('page_info', {})
    report.append("\n PAGE INFORMATION:")
    report.append(f"  • Title: {page_info.get('title', 'N/A')}")
    report.append(f"  • Final URL: {page_info.get('current_url', 'N/A')}")
    report.append(f"  • Load Time: {page_info.get('load_time', 0):.2f} seconds")
    report.append(f"  • Page Size: {page_info.get('page_source_length', 0):,} characters")

    # Structure Analysis
    report.append("\n PAGE STRUCTURE:")
    report.append(f"  • Total Links: {page_info.get('total_links', 0)}")
    report.append(f"  • External Links: {page_info.get('external_links', 0)}")
    report.append(f"  • Scripts: {page_info.get('total_scripts', 0)}")
    report.append(f"  • External Scripts: {page_info.get('external_scripts', 0)}")
    report.append(f"  • Iframes: {page_info.get('iframes', 0)}")
    report.append(f"  • Forms: {page_info.get('forms', 0)}")
    report.append(f"  • Suspicious Inputs: {page_info.get('suspicious_inputs', 0)}")

    # Redirects
    redirects = analysis_result.get('redirects', [])
    if redirects:
        report.append("\nREDIRECTS:")
        for redirect in redirects:
            report.append(f"  • {redirect.get('original', 'N/A')} → {redirect.get('final', 'N/A')}")

    # Network Requests
    network_requests = analysis_result.get('network_requests', [])
    if network_requests:
        # Count by type
        requests_count = len([r for r in network_requests if r.get('type') == 'request'])
        report.append(f"\n🌐 NETWORK ACTIVITY:")
        report.append(f"  • Total Requests: {requests_count}")

        # Show unique domains
        domains = set()
        for req in network_requests:
            if req.get('type') == 'request' and req.get('url'):
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(req['url']).netloc
                    if domain:
                        domains.add(domain)
                except:
                    pass

        if domains:
            report.append(f"  • Unique Domains: {len(domains)}")
            for domain in list(domains)[:10]:
                report.append(f"    - {domain}")

    # Security Indicators
    security_indicators = analysis_result.get('security_indicators', [])
    if security_indicators:
        report.append("\n⚠SECURITY INDICATORS:")
        for indicator in security_indicators:
            emoji = "" if indicator.get('type') == 'warning' else "🔍"
            report.append(f"  {emoji} {indicator.get('message', '')}")
    else:
        report.append("\n✅ No significant security issues detected")

    # Console Logs (errors and warnings only)
    console_logs = analysis_result.get('console_logs', [])
    errors = [log for log in console_logs if log.get('level') == 'SEVERE']
    if errors:
        report.append(f"\n CONSOLE ERRORS ({len(errors)}):")
        for error in errors[:5]:
            report.append(f"  • {error.get('message', 'N/A')[:200]}")

    # Resource Summary
    resources = analysis_result.get('resources', [])
    if resources:
        total_size = sum(r.get('size', 0) for r in resources)
        report.append(f"\n RESOURCE SUMMARY:")
        report.append(f"  • Total Resources: {len(resources)}")
        report.append(f"  • Total Transfer Size: {total_size / 1024:.2f} KB")

        # Type breakdown
        from collections import Counter
        types = Counter(r.get('type', 'unknown') for r in resources)
        report.append(f"  • Resource Types:")
        for type_name, count in types.most_common(5):
            report.append(f"    - {type_name}: {count}")

    return "\n".join(report)


class HeadlessBrowserAnalyzer:

    def __init__(self, user_data_dir: Optional[str] = None, use_sandbox: bool = True):
        """
        Initialize the headless browser analyzer

        Args:
            user_data_dir: Custom directory for Chrome user data (isolated profile)
            use_sandbox: Enable Chrome sandboxing for security
        """
        self.user_data_dir = user_data_dir or tempfile.mkdtemp(prefix="chrome_sandbox_")
        self.use_sandbox = use_sandbox
        self.driver = None
        self.analysis_data = {
            'url': None,
            'timestamp': None,
            'page_info': {},
            'network_requests': [],
            'console_logs': [],
            'screenshots': {},
            'redirects': [],
            'popups': [],
            'security_indicators': [],
            'resources': []
        }

    def _create_secure_chrome_options(self) -> Options:
        """Create Chrome options with maximum security and sandboxing"""
        chrome_options = Options()

        # Essential headless and sandboxing options
        chrome_options.add_argument('--headless=new')  # New headless mode
        chrome_options.add_argument('--no-sandbox')  # Required in some environments
        chrome_options.add_argument('--disable-dev-shm-usage')  # Overcome limited resource issues

        # Security and isolation options
        if self.use_sandbox:
            chrome_options.add_argument('--sandbox')  # Enable Chrome sandboxing
        chrome_options.add_argument('--disable-web-security')  # Disable for analysis (optional)
        chrome_options.add_argument('--disable-features=VizDisplayCompositor')
        chrome_options.add_argument('--disable-gpu')  # Disable GPU for headless
        chrome_options.add_argument('--disable-software-rasterizer')

        # Privacy and tracking protection
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-popup-blocking')  # Allow popups for detection
        chrome_options.add_argument('--disable-notifications')
        chrome_options.add_argument('--disable-default-apps')

        # Network and resource limits
        chrome_options.add_argument('--max_old_space_size=512')  # Memory limit
        chrome_options.add_argument('--disk-cache-size=0')  # Disable disk cache
        chrome_options.add_argument('--media-cache-size=0')

        # Fingerprinting protection
        chrome_options.add_argument('--disable-client-side-phishing-detection')
        chrome_options.add_argument('--disable-component-update')

        # User agent spoofing (optional, for analysis)
        chrome_options.add_argument(
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36')

        # Use isolated profile
        chrome_options.add_argument(f'--user-data-dir={self.user_data_dir}')

        # Performance and logging
        chrome_options.add_argument('--log-level=3')  # Only fatal errors
        chrome_options.add_argument('--silent')

        # Enable performance logging for network capture
        caps = DesiredCapabilities.CHROME
        caps['goog:loggingPrefs'] = {'performance': 'ALL', 'browser': 'ALL'}
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL', 'browser': 'ALL'})

        # Experimental options
        prefs = {
            'profile.default_content_setting_values': {
                'cookies': 2,  # Block cookies
                'images': 2,  # Don't load images for speed
                'javascript': 1,  # Enable JS for analysis
                'plugins': 2,  # Block plugins
                'popups': 2,  # Block popups
                'notifications': 2  # Block notifications
            },
            'profile.block_third_party_cookies': True,
            'profile.default_content_settings.popups': 0
        }
        chrome_options.add_experimental_option('prefs', prefs)

        return chrome_options

    def _setup_driver(self):
        """Setup Chrome driver with safe configurations"""
        try:
            chrome_options = self._create_secure_chrome_options()

            # Auto-detect ChromeDriver or use from PATH
            service = Service()  # Will use chromedriver from PATH

            self.driver = webdriver.Chrome(
                service=service,
                options=chrome_options
            )

            # Set timeouts
            self.driver.set_page_load_timeout(30)
            self.driver.set_script_timeout(30)

            logger.info("Headless Chrome driver initialized successfully with sandboxing")
            return True

        except WebDriverException as e:
            logger.error(f"Failed to initialize Chrome driver: {e}")
            logger.error("Make sure Chrome and ChromeDriver are installed")
            return False

    async def _capture_network_requests(self):
        """Capture network requests using performance logs"""
        if not self.driver:
            return

        logs = self.driver.get_log('performance')
        for log in logs:
            try:
                log_data = json.loads(log['message'])
                message = log_data.get('message', {})
                method = message.get('method', '')

                if method == 'Network.requestWillBeSent':
                    request = message.get('params', {})
                    request_data = {
                        'url': request.get('request', {}).get('url'),
                        'method': request.get('request', {}).get('method'),
                        'timestamp': request.get('timestamp'),
                        'type': 'request'
                    }
                    self.analysis_data['network_requests'].append(request_data)

                elif method == 'Network.responseReceived':
                    response = message.get('params', {})
                    response_data = {
                        'url': response.get('response', {}).get('url'),
                        'status': response.get('response', {}).get('status'),
                        'timestamp': response.get('timestamp'),
                        'type': 'response'
                    }
                    self.analysis_data['network_requests'].append(response_data)

            except json.JSONDecodeError:
                continue

    def _capture_console_logs(self):
        """Capture browser console logs"""
        if not self.driver:
            return

        logs = self.driver.get_log('browser')
        for log in logs:
            self.analysis_data['console_logs'].append({
                'level': log['level'],
                'message': log['message'],
                'timestamp': log['timestamp']
            })

    def _capture_page_info(self):
        """Capture comprehensive page information"""
        try:
            page_info = {
                'title': self.driver.title,
                'current_url': self.driver.current_url,
                'page_source_length': len(self.driver.page_source),
                'cookies': self.driver.get_cookies(),
                'window_size': self.driver.get_window_size(),
                'local_storage': self.driver.execute_script("return Object.entries(localStorage);"),
                'session_storage': self.driver.execute_script("return Object.entries(sessionStorage);")
            }

            # Get all links
            links = self.driver.find_elements(By.TAG_NAME, 'a')
            page_info['total_links'] = len(links)
            page_info['external_links'] = len([
                link for link in links
                if link.get_attribute('href') and
                   not link.get_attribute('href').startswith(self.analysis_data['url'])
            ])

            # Get all scripts
            scripts = self.driver.find_elements(By.TAG_NAME, 'script')
            page_info['total_scripts'] = len(scripts)
            page_info['external_scripts'] = len([
                script for script in scripts
                if script.get_attribute('src')
            ])

            # Get iframes
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            page_info['iframes'] = len(iframes)

            # Get forms
            forms = self.driver.find_elements(By.TAG_NAME, 'form')
            page_info['forms'] = len(forms)

            # Check for suspicious elements
            suspicious_inputs = []
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    input_type = input_elem.get_attribute('type')
                    if input_type in ['password', 'hidden']:
                        suspicious_inputs.append(input_type)
            page_info['suspicious_inputs'] = len(suspicious_inputs)

            self.analysis_data['page_info'] = page_info

        except Exception as e:
            logger.error(f"Error capturing page info: {e}")

    def _capture_screenshots(self):
        """Capture screenshots at different stages"""
        try:
            # Full page screenshot
            screenshot_full = self.driver.get_screenshot_as_base64()
            self.analysis_data['screenshots']['full_page'] = screenshot_full

            # Capture viewport
            viewport = self.driver.execute_script("""
                return {
                    width: window.innerWidth,
                    height: window.innerHeight
                };
            """)
            self.analysis_data['screenshots']['viewport_size'] = viewport

        except Exception as e:
            logger.error(f"Error capturing screenshots: {e}")

    def _detect_security_indicators(self):
        """Detect security-related indicators"""
        indicators = []

        try:
            # Check for SSL/TLS issues
            current_url = self.driver.current_url
            if current_url.startswith('http://'):
                indicators.append({
                    'type': 'warning',
                    'message': 'Page loaded over insecure HTTP connection'
                })

            # Check for mixed content
            if 'https://' in current_url:
                mixed_content = self.driver.execute_script("""
                    const resources = performance.getEntriesByType('resource');
                    return resources.filter(r => 
                        r.initiatorType === 'img' && 
                        r.name.startsWith('http://')
                    ).length;
                """)
                if mixed_content > 0:
                    indicators.append({
                        'type': 'warning',
                        'message': f'Mixed content detected: {mixed_content} insecure resources'
                    })

            # Check for suspicious JavaScript patterns
            suspicious_patterns = []
            page_source = self.driver.page_source.lower()

            patterns = {
                'eval_usage': 'eval(' in page_source,
                'document_write': 'document.write(' in page_source,
                'crypto_miner': 'coinhive' in page_source or 'cryptonight' in page_source,
                'iframe_redirect': 'top.location' in page_source and 'iframe' in page_source,
                'encoded_scripts': '%3cscript%3e' in page_source or '&#x' in page_source
            }

            for pattern, detected in patterns.items():
                if detected:
                    suspicious_patterns.append(pattern)

            if suspicious_patterns:
                indicators.append({
                    'type': 'suspicious',
                    'message': f'Suspicious patterns detected: {", ".join(suspicious_patterns)}'
                })

            # Check for redirects
            if len(self.analysis_data['redirects']) > 2:
                indicators.append({
                    'type': 'warning',
                    'message': f'Multiple redirects detected: {len(self.analysis_data["redirects"])}'
                })

            self.analysis_data['security_indicators'] = indicators

        except Exception as e:
            logger.error(f"Error detecting security indicators: {e}")

    async def analyze_url(self, url: str, wait_time: int = 5, capture_network: bool = True) -> Dict[str, Any]:
        """
        Analyze a URL in headless sandboxed browser

        Args:
            url: The URL to analyze
            wait_time: Seconds to wait for page to load and dynamic content
            capture_network: Whether to capture network requests

        Returns:
            Dictionary with analysis results
        """
        self.analysis_data['url'] = url
        self.analysis_data['timestamp'] = datetime.now().isoformat()

        # Setup driver
        if not self._setup_driver():
            return {'error': 'Failed to initialize browser driver'}

        try:
            logger.info(f"Analyzing URL in headless mode: {url}")

            # Navigate to URL
            start_time = time.time()
            self.driver.get(url)
            load_time = time.time() - start_time
            self.analysis_data['page_info']['load_time'] = load_time

            # Track redirects
            current_url = self.driver.current_url
            if current_url != url:
                self.analysis_data['redirects'].append({
                    'original': url,
                    'final': current_url
                })

            # Wait for page to be fully loaded
            try:
                WebDriverWait(self.driver, wait_time).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                # Additional wait for dynamic content
                await asyncio.sleep(2)
            except TimeoutException:
                logger.warning(f"Page load timeout after {wait_time} seconds")

            # Capture various aspects
            self._capture_page_info()

            if capture_network:
                await self._capture_network_requests()

            self._capture_console_logs()
            self._capture_screenshots()
            self._detect_security_indicators()

            # Capture all resources
            resources = self.driver.execute_script("""
                return performance.getEntriesByType('resource').map(r => ({
                    name: r.name,
                    type: r.initiatorType,
                    duration: r.duration,
                    size: r.transferSize || 0
                }));
            """)
            self.analysis_data['resources'] = resources[:100]  # Limit to 100 resources

            logger.info(f"Analysis completed for {url}")

        except TimeoutException:
            self.analysis_data['error'] = f"Timeout loading URL after 30 seconds"

        except Exception as e:
            logger.error(f"Error analyzing URL: {e}")
            self.analysis_data['error'] = str(e)

        finally:
            # Clean up
            if self.driver:
                self.driver.quit()

            # Clean up user data directory
            try:
                shutil.rmtree(self.user_data_dir, ignore_errors=True)
            except:
                pass

        return self.analysis_data

