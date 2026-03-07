from app.core.config import settings


def test_settings_load():
    assert settings.app_name == "Aletheia"
