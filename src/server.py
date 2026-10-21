from backend.application import create_application
from backend.config import Settings
from backend.http_api import create_app


def main():
    settings = Settings.from_environment()
    application = create_application(settings)
    server = create_app(application)
    print(
        "Tablero sintético disponible en http://{}:{}/".format(settings.host, settings.port),
        flush=True,
    )
    print("Solo escucha en localhost; no exponga este prototipo a redes externas.", flush=True)
    try:
        server.run(host=settings.host, port=settings.port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\nServidor detenido.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
