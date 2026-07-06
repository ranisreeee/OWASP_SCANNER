"""
Unit tests for the OWASP Scanner
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from owasp_scanner.scanner import OWASPScanner, Vulnerability, Severity


class TestOWASPScanner:
    """Test cases for the OWASP Scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        return OWASPScanner("http://test.com", timeout=5)
    
    @pytest.fixture
    def mock_response(self):
        """Create a mock response object."""
        response = Mock()
        response.status_code = 200
        response.text = ""
        response.headers = {}
        response.cookies = MagicMock()
        response.cookies.get_dict.return_value = {}
        return response
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.target_url == "http://test.com"
        assert scanner.timeout == 5
        assert len(scanner.vulnerabilities) == 0
    
    def test_vulnerability_creation(self):
        """Test vulnerability dataclass."""
        vuln = Vulnerability(
            id="TEST-001",
            name="Test Vuln",
            severity=Severity.HIGH,
            description="Test description",
            evidence="Test evidence",
            remediation="Fix it",
            url="http://test.com"
        )
        assert vuln.id == "TEST-001"
        assert vuln.severity == Severity.HIGH
    
    def test_report_generation(self, scanner):
        """Test report generation."""
        # Add a test vulnerability
        scanner.vulnerabilities.append(Vulnerability(
            id="TEST-001",
            name="Test Vulnerability",
            severity=Severity.HIGH,
            description="Test",
            evidence="Test evidence",
            remediation="Fix it",
            url="http://test.com"
        ))
        
        # Test JSON report
        json_report = scanner.generate_report(output_format="json")
        report_data = json.loads(json_report)
        assert report_data['scan_info']['total_vulnerabilities'] == 1
        assert report_data['vulnerabilities'][0]['name'] == "Test Vulnerability"
        
        # Test HTML report
        html_report = scanner.generate_report(output_format="html")
        assert "<html>" in html_report
        assert "Test Vulnerability" in html_report
        
        # Test text report
        text_report = scanner.generate_report(output_format="text")
        assert "Test Vulnerability" in text_report


if __name__ == '__main__':
    pytest.main([__file__, '-v'])