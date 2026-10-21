from werkzeug.middleware.proxy_fix import ProxyFix

from backend.application import create_application
from backend.config import Settings
from backend.http_api import create_app


application = create_application(Settings.from_environment())
app = ProxyFix(create_app(application), x_for=1, x_proto=1, x_host=1, x_port=1)
