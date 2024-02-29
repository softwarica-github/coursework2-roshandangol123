import unittest
from unittest.mock import patch
import os
from roshan import FileIntegrityChecker

class TestFileIntegrityChecker(unittest.TestCase):

    def setUp(self):
        self.file_checker = FileIntegrityChecker()

    def test_calculate_hash(self):
        # Mocking a file for testing
        with patch('builtins.open', unittest.mock.mock_open(read_data=b'Test data')) as mock_file:
            hash_value = self.file_checker.calculate_hash('test_file.txt')
            mock_file.assert_called_once_with('test_file.txt', 'rb')
            # self.assertEqual(hash_value, '532eaabd9574880dbf76b9b28e6c5cc3')

    def test_store_and_check_hash(self):
        self.file_checker.store_hash('test_file.txt', '532eaabd9574880dbf76b9b28e6c5cc3')
        self.assertTrue(self.file_checker.check_hash('test_file.txt', '532eaabd9574880dbf76b9b28e6c5cc3'))
        self.assertFalse(self.file_checker.check_hash('test_file.txt', 'invalid_hash_value'))

    def test_remove_file(self):
        self.file_checker.imported_files = {'test_file.txt': '532eaabd9574880dbf76b9b28e6c5cc3'}
        self.file_checker.remove_file('test_file.txt')
        self.assertNotIn('test_file.txt', self.file_checker.imported_files)

if __name__ == '__main__':
    unittest.main()
