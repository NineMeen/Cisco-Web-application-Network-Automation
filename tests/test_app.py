import unittest
import io
import sys
import os

# Add parent directory to sys.path to resolve 'app' import correctly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

class TestAppImportBackup(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_import_backup_no_file_part(self):
        """Test import_backup when no file part is present in the request."""
        response = self.app.post('/import_backup', data={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'error', 'message': 'No file part'})

    def test_import_backup_empty_filename(self):
        """Test import_backup when a file part is present but the filename is empty."""
        data = {
            'backupFile': (io.BytesIO(b"dummy data"), '')
        }
        response = self.app.post('/import_backup', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'error', 'message': 'No selected file'})

if __name__ == '__main__':
    unittest.main()
