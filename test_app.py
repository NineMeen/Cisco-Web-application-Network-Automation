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
