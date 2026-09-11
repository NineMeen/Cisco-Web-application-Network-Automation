import pytest
from app import app as flask_app, allowed_file

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


def test_allowed_extensions():
    assert allowed_file('config.txt') is True
    assert allowed_file('server.conf') is True

def test_mixed_case_extensions():
    assert allowed_file('config.TXT') is True
    assert allowed_file('server.CoNf') is True

def test_multiple_dots():
    assert allowed_file('archive.backup.txt') is True
    assert allowed_file('my.new.server.conf') is True

def test_invalid_extensions():
    assert allowed_file('script.py') is False
    assert allowed_file('image.png') is False
    assert allowed_file('document.pdf') is False

def test_no_extension():
    assert allowed_file('configfile') is False
    assert allowed_file('server') is False

def test_dot_but_no_extension():
    assert allowed_file('config.') is False

def test_hidden_file():
    assert allowed_file('.txt') is True
    assert allowed_file('.gitignore') is False
