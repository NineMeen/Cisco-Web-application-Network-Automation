import unittest
from app import subnet_to_wildcard

class TestSubnetToWildcard(unittest.TestCase):
    def test_standard_class_c(self):
        """Test a typical Class C subnet mask"""
        self.assertEqual(subnet_to_wildcard('255.255.255.0'), '0.0.0.255')

    def test_standard_class_b(self):
        """Test a typical Class B subnet mask"""
        self.assertEqual(subnet_to_wildcard('255.255.0.0'), '0.0.255.255')

    def test_standard_class_a(self):
        """Test a typical Class A subnet mask"""
        self.assertEqual(subnet_to_wildcard('255.0.0.0'), '0.255.255.255')

    def test_host_route(self):
        """Test a /32 host route mask"""
        self.assertEqual(subnet_to_wildcard('255.255.255.255'), '0.0.0.0')

    def test_default_route(self):
        """Test a /0 default route mask"""
        self.assertEqual(subnet_to_wildcard('0.0.0.0'), '255.255.255.255')

    def test_variable_length_subnets(self):
        """Test various other common subnet masks"""
        self.assertEqual(subnet_to_wildcard('255.255.255.128'), '0.0.0.127')
        self.assertEqual(subnet_to_wildcard('255.255.255.192'), '0.0.0.63')
        self.assertEqual(subnet_to_wildcard('255.255.255.224'), '0.0.0.31')
        self.assertEqual(subnet_to_wildcard('255.255.255.240'), '0.0.0.15')
        self.assertEqual(subnet_to_wildcard('255.255.255.248'), '0.0.0.7')
        self.assertEqual(subnet_to_wildcard('255.255.255.252'), '0.0.0.3')
        self.assertEqual(subnet_to_wildcard('255.255.254.0'), '0.0.1.255')
        self.assertEqual(subnet_to_wildcard('255.255.240.0'), '0.0.15.255')

    def test_malformed_input_value_error(self):
        """Test that invalid string octets raise ValueError (due to int parsing)"""
        with self.assertRaises(ValueError):
            subnet_to_wildcard('255.255.abc.0')

if __name__ == '__main__':
    unittest.main()
