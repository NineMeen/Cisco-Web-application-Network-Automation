import pytest
from app import app as flask_app

@pytest.fixture
def app():
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

def test_index_redirects_to_login_without_session(client):
    response = client.get('/')
    assert response.status_code == 302
    assert response.location.endswith('/login')

def test_index_redirects_to_main_with_session(client):
    with client.session_transaction() as sess:
        sess['logged_in'] = True
    response = client.get('/')
    assert response.status_code == 302
    assert response.location.endswith('/main')

from app import allowed_file

def test_allowed_file_valid_extensions():
    assert allowed_file("config.txt") is True
    assert allowed_file("backup.conf") is True

def test_allowed_file_case_insensitivity():
    assert allowed_file("config.TXT") is True
    assert allowed_file("backup.CoNf") is True

def test_allowed_file_invalid_extensions():
    assert allowed_file("script.py") is False
    assert allowed_file("document.pdf") is False
    assert allowed_file("image.png") is False

def test_allowed_file_no_extension():
    assert allowed_file("file_without_extension") is False

def test_allowed_file_hidden_file():
    assert allowed_file(".txt") is True
    assert allowed_file(".conf") is True
    assert allowed_file(".hidden") is False

def test_allowed_file_multiple_dots():
    assert allowed_file("archive.backup.txt") is True
    assert allowed_file("archive.backup.tar.gz") is False

def test_allowed_file_empty_string():
    assert allowed_file("") is False
