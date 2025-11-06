"""
Business Logic Testing Module
Tests for business logic vulnerabilities and abuse cases
"""
from typing import Dict, List
from utils.logger import get_logger
logger = get_logger(__name__)
class BusinessLogicTester:
    """Test business logic vulnerabilities."""
    def __init__(self, http_client, config: Dict):
        """Initialize business logic tester."""
        self.http_client = http_client
        self.config = config
    def test_business_logic(self, url: str, context: Dict) -> List[Dict]:
        """
        Test for business logic vulnerabilities.
        Args:
            url: Target URL
            context: Request context including forms, parameters
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        vulnerabilities.extend(self._test_price_manipulation(url, context))
        vulnerabilities.extend(self._test_quantity_manipulation(url, context))
        vulnerabilities.extend(self._test_workflow_bypass(url, context))
        vulnerabilities.extend(self._test_race_conditions(url, context))
        vulnerabilities.extend(self._test_coupon_abuse(url, context))
        vulnerabilities.extend(self._test_referral_abuse(url, context))
        vulnerabilities.extend(self._test_limit_bypass(url, context))
        return vulnerabilities
    def _test_price_manipulation(self, url: str, context: Dict) -> List[Dict]:
        """Test for price manipulation vulnerabilities."""
        vulnerabilities = []
        price_params = ['price', 'amount', 'total', 'cost', 'value']
        for param in price_params:
            if param in url.lower() or any(param in str(f) for f in context.get('forms', [])):
                test_values = [-1, -100, 0, 0.01]
                for value in test_values:
                    try:
                        if '?' in url:
                            test_url = f"{url}&{param}={value}"
                        else:
                            test_url = f"{url}?{param}={value}"
                        response = self.http_client.post(
                            test_url,
                            data={param: value}
                        )
                        if response and response.status_code in [200, 201]:
                            vulnerabilities.append({
                                'type': 'Business Logic - Price Manipulation',
                                'severity': 'critical',
                                'url': url,
                                'parameter': param,
                                'evidence': f'Negative/zero price value accepted: {value}',
                                'description': 'Application accepts manipulated price values',
                                'remediation': 'Validate prices server-side, never trust client input',
                                'business_impact': 'Financial loss, fraud'
                            })
                            break
                    except Exception as e:
                        logger.debug(f"Error testing price manipulation: {e}")
        return vulnerabilities
    def _test_quantity_manipulation(self, url: str, context: Dict) -> List[Dict]:
        """Test for quantity manipulation vulnerabilities."""
        vulnerabilities = []
        quantity_params = ['quantity', 'qty', 'amount', 'count']
        for param in quantity_params:
            test_values = [-1, 0, 999999, 2147483647]  # Including max int
            for value in test_values:
                try:
                    response = self.http_client.post(
                        url,
                        data={param: value}
                    )
                    if response and response.status_code in [200, 201]:
                        if value < 0:
                            vulnerabilities.append({
                                'type': 'Business Logic - Negative Quantity',
                                'severity': 'high',
                                'url': url,
                                'parameter': param,
                                'evidence': f'Negative quantity accepted: {value}',
                                'description': 'Application accepts negative quantity values',
                                'remediation': 'Implement positive integer validation for quantities',
                                'business_impact': 'Inventory manipulation, fraud'
                            })
                        elif value > 1000000:
                            vulnerabilities.append({
                                'type': 'Business Logic - Excessive Quantity',
                                'severity': 'medium',
                                'url': url,
                                'parameter': param,
                                'evidence': f'Excessive quantity accepted: {value}',
                                'description': 'Application lacks quantity limits',
                                'remediation': 'Implement reasonable quantity limits',
                                'business_impact': 'Resource exhaustion, DoS'
                            })
                        break
                except Exception as e:
                    logger.debug(f"Error testing quantity manipulation: {e}")
        return vulnerabilities
    def _test_workflow_bypass(self, url: str, context: Dict) -> List[Dict]:
        """Test for workflow bypass vulnerabilities."""
        vulnerabilities = []
        workflow_indicators = [
            'step', 'stage', 'phase', 'status', 
            'checkout', 'payment', 'confirm', 'verify'
        ]
        for indicator in workflow_indicators:
            if indicator in url.lower():
                try:
                    bypass_urls = [
                        url.replace(f'{indicator}=1', f'{indicator}=3'),
                        url.replace(f'{indicator}=2', f'{indicator}=5'),
                        url.replace(f'/{indicator}/1/', f'/{indicator}/final/'),
                    ]
                    for bypass_url in bypass_urls:
                        response = self.http_client.get(bypass_url)
                        if response and response.status_code == 200:
                            if 'complete' in response.text.lower() or 'success' in response.text.lower():
                                vulnerabilities.append({
                                    'type': 'Business Logic - Workflow Bypass',
                                    'severity': 'high',
                                    'url': url,
                                    'evidence': f'Successfully bypassed workflow steps',
                                    'description': 'Application allows skipping workflow steps',
                                    'remediation': 'Implement server-side workflow state validation',
                                    'business_impact': 'Payment bypass, unauthorized access'
                                })
                                break
                except Exception as e:
                    logger.debug(f"Error testing workflow bypass: {e}")
        return vulnerabilities
    def _test_race_conditions(self, url: str, context: Dict) -> List[Dict]:
        """Test for race condition vulnerabilities."""
        vulnerabilities = []
        race_indicators = ['withdraw', 'transfer', 'redeem', 'claim', 'use']
        if any(indicator in url.lower() for indicator in race_indicators):
            try:
                import concurrent.futures
                responses = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self.http_client.post, url) for _ in range(10)]
                    responses = [f.result() for f in concurrent.futures.as_completed(futures)]
                success_count = sum(1 for r in responses if r and r.status_code in [200, 201])
                if success_count > 1:
                    vulnerabilities.append({
                        'type': 'Business Logic - Race Condition',
                        'severity': 'critical',
                        'url': url,
                        'evidence': f'{success_count} simultaneous requests succeeded',
                        'description': 'Application vulnerable to race condition attacks',
                        'remediation': 'Implement proper locking mechanisms and idempotency',
                        'business_impact': 'Double-spending, resource duplication'
                    })
            except Exception as e:
                logger.debug(f"Error testing race conditions: {e}")
        return vulnerabilities
    def _test_coupon_abuse(self, url: str, context: Dict) -> List[Dict]:
        """Test for coupon/promo code abuse."""
        vulnerabilities = []
        coupon_params = ['coupon', 'promo', 'discount', 'voucher', 'code']
        for param in coupon_params:
            if param in url.lower():
                try:
                    test_data = {
                        param: 'TEST123',
                        f'{param}_2': 'TEST456',
                        f'{param}[]': ['TEST123', 'TEST456']
                    }
                    response = self.http_client.post(url, data=test_data)
                    if response and response.status_code in [200, 201]:
                        if 'discount' in response.text.lower():
                            vulnerabilities.append({
                                'type': 'Business Logic - Coupon Stacking',
                                'severity': 'medium',
                                'url': url,
                                'evidence': 'Multiple coupons may be stackable',
                                'description': 'Application may allow stacking multiple discount codes',
                                'remediation': 'Limit to one coupon per transaction',
                                'business_impact': 'Revenue loss, excessive discounts'
                            })
                except Exception as e:
                    logger.debug(f"Error testing coupon abuse: {e}")
        return vulnerabilities
    def _test_referral_abuse(self, url: str, context: Dict) -> List[Dict]:
        """Test for referral program abuse."""
        vulnerabilities = []
        referral_indicators = ['referral', 'refer', 'invite', 'affiliate']
        if any(indicator in url.lower() for indicator in referral_indicators):
            try:
                response = self.http_client.post(
                    url,
                    data={'referrer': 'user123', 'referee': 'user123'}
                )
                if response and response.status_code in [200, 201]:
                    if 'success' in response.text.lower() or 'reward' in response.text.lower():
                        vulnerabilities.append({
                            'type': 'Business Logic - Self-Referral',
                            'severity': 'medium',
                            'url': url,
                            'evidence': 'Self-referral appears to be accepted',
                            'description': 'Application may allow users to refer themselves',
                            'remediation': 'Validate referrer != referee',
                            'business_impact': 'Bonus abuse, fraud'
                        })
            except Exception as e:
                logger.debug(f"Error testing referral abuse: {e}")
        return vulnerabilities
    def _test_limit_bypass(self, url: str, context: Dict) -> List[Dict]:
        """Test for limit bypass vulnerabilities."""
        vulnerabilities = []
        limit_indicators = ['download', 'export', 'send', 'share']
        if any(indicator in url.lower() for indicator in limit_indicators):
            try:
                success_count = 0
                for i in range(50):
                    response = self.http_client.get(url)
                    if response and response.status_code == 200:
                        success_count += 1
                if success_count >= 45:  # 90% success rate
                    vulnerabilities.append({
                        'type': 'Business Logic - Limit Bypass',
                        'severity': 'medium',
                        'url': url,
                        'evidence': f'{success_count}/50 requests succeeded without limiting',
                        'description': 'Application lacks proper rate limiting',
                        'remediation': 'Implement per-user action limits',
                        'business_impact': 'Resource abuse, data exfiltration'
                    })
            except Exception as e:
                logger.debug(f"Error testing limit bypass: {e}")
        return vulnerabilities
