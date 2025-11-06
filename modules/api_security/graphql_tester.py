"""
GraphQL Security Testing Module
Tests GraphQL endpoints for specific vulnerabilities
"""
import json
from typing import Dict, List
from utils.logger import get_logger
logger = get_logger(__name__)
class GraphQLTester:
    """GraphQL-specific security testing."""
    def __init__(self, http_client):
        """Initialize GraphQL tester."""
        self.http_client = http_client
    def test_graphql_endpoint(self, url: str) -> List[Dict]:
        """Test GraphQL endpoint for vulnerabilities."""
        vulnerabilities = []
        vulnerabilities.extend(self._test_introspection(url))
        vulnerabilities.extend(self._test_depth_limit(url))
        vulnerabilities.extend(self._test_batch_attacks(url))
        vulnerabilities.extend(self._test_field_suggestions(url))
        return vulnerabilities
    def _test_introspection(self, url: str) -> List[Dict]:
        """Test if GraphQL introspection is enabled."""
        vulnerabilities = []
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            """
        }
        try:
            response = self.http_client.post(url, json=introspection_query)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if '__schema' in str(data):
                        vulnerabilities.append({
                            'type': 'GraphQL - Introspection Enabled',
                            'severity': 'medium',
                            'url': url,
                            'evidence': 'GraphQL introspection query succeeded',
                            'description': 'GraphQL introspection is enabled in production',
                            'remediation': 'Disable introspection in production environments'
                        })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"Error testing GraphQL introspection: {e}")
        return vulnerabilities
    def _test_depth_limit(self, url: str) -> List[Dict]:
        """Test for query depth limiting."""
        vulnerabilities = []
        deep_query = {
            "query": """
            {
                user {
                    posts {
                        comments {
                            author {
                                posts {
                                    comments {
                                        author {
                                            posts {
                                                comments {
                                                    id
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        try:
            response = self.http_client.post(url, json=deep_query)
            if response and response.status_code == 200:
                vulnerabilities.append({
                    'type': 'GraphQL - No Depth Limit',
                    'severity': 'high',
                    'url': url,
                    'evidence': 'Deeply nested query (8+ levels) executed successfully',
                    'description': 'GraphQL endpoint lacks query depth limiting',
                    'remediation': 'Implement query depth limiting (max 5-7 levels)'
                })
        except Exception as e:
            logger.debug(f"Error testing GraphQL depth limit: {e}")
        return vulnerabilities
    def _test_batch_attacks(self, url: str) -> List[Dict]:
        """Test for batch query attacks."""
        vulnerabilities = []
        batch_query = {
            "query": """
            query {
                q1: user(id: 1) { id }
                q2: user(id: 2) { id }
                q3: user(id: 3) { id }
                """ + "\n".join([f"q{i}: user(id: {i}) {{ id }}" for i in range(4, 100)]) + """
            }
            """
        }
        try:
            response = self.http_client.post(url, json=batch_query)
            if response and response.status_code == 200:
                vulnerabilities.append({
                    'type': 'GraphQL - Batch Query DoS',
                    'severity': 'medium',
                    'url': url,
                    'evidence': '100 queries in single request succeeded',
                    'description': 'GraphQL allows unrestricted batch queries (DoS risk)',
                    'remediation': 'Limit number of queries per request'
                })
        except Exception as e:
            logger.debug(f"Error testing GraphQL batch attacks: {e}")
        return vulnerabilities
    def _test_field_suggestions(self, url: str) -> List[Dict]:
        """Test for field suggestion information disclosure."""
        vulnerabilities = []
        typo_query = {
            "query": "{ usr { id } }"  # 'usr' instead of 'user'
        }
        try:
            response = self.http_client.post(url, json=typo_query)
            if response and 'did you mean' in response.text.lower():
                vulnerabilities.append({
                    'type': 'GraphQL - Field Suggestions Enabled',
                    'severity': 'low',
                    'url': url,
                    'evidence': 'GraphQL returns field suggestions for typos',
                    'description': 'Field suggestions may leak schema information',
                    'remediation': 'Disable field suggestions in production'
                })
        except Exception as e:
            logger.debug(f"Error testing GraphQL field suggestions: {e}")
        return vulnerabilities
