# Faro — tablero de gestión de alertas

Prototipo académico de workflow y auditoría AML/fraude. Todos los usuarios, alertas y referencias de evidencia son sintéticos; no se integra con plataformas institucionales ni se reciben archivos.

## Ejecutar

Requiere Python 3.10 o superior. Instala las dependencias del backend:

```powershell
python -m pip install -r requirements.txt
python src\server.py
```

Abre <http://127.0.0.1:8765/>. La primera ejecución crea `src\data\alerts.sqlite3`, genera una contraseña aleatoria por cuenta y la muestra una sola vez en la consola. Guárdalas para la demo. Si se pierde una contraseña, detén el servidor y elimina `src\data\alerts.sqlite3` y, si existen, sus archivos `-wal`/`-shm`; el siguiente inicio recreará las credenciales y la muestra sintética. Para elegir otra ubicación de la base, define `ALERTS_DB`; para cambiar el puerto local, define `PORT`.

## Arquitectura

El backend usa módulos con responsabilidades separadas:

- `src\backend\http_api.py`: rutas HTTP, validación de solicitudes, serialización y encabezados.
- `src\backend\services.py`: reglas del workflow, roles, transiciones, métricas y segregación de funciones.
- `src\backend\repository.py`: consultas y escrituras del dominio.
- `src\backend\database.py`: conexiones, esquema y transacciones SQLite/PostgreSQL.
- `src\backend\security.py`: hash de contraseñas, límite de intentos y sesiones.
- `src\backend\seed.py`: creación idempotente de cuentas y datos de demo.
- `src\backend\config.py`: configuración y valores por defecto; `src\server.py` compone e inicia la aplicación.

SQLite sigue disponible para desarrollo local; PostgreSQL es el almacenamiento recomendado para el despliegue. En ambos casos la interfaz consume la API Flask, el dominio está separado de HTTP y el repositorio encapsula las consultas. Las alertas y excepciones sintéticas se siembran si no existen alertas; las credenciales solo se generan si no hay usuarios. Los cambios se conservan entre reinicios.

## Despliegue de demostración en Render

El repositorio incluye `render.yaml` para crear un servicio web y una base PostgreSQL. Conecta el repositorio en Render usando **New + → Blueprint** y aplica el blueprint. Render instala `requirements.txt` y ejecuta Gunicorn sobre `src\wsgi.py`; no se debe ejecutar el servidor de desarrollo `python src\server.py` en el servicio publicado. El servidor local continúa disponible para desarrollo y pruebas.

El blueprint genera contraseñas secretas para las cinco cuentas sintéticas de demo como variables del servicio; no las imprime en los logs. Consúltalas en el panel de variables de entorno de Render. Los usuarios se crean al inicializar una base nueva. Para cambios posteriores de contraseñas, actualiza la base de forma administrada o recrea la base de demo después de respaldar lo necesario.

El servicio configura HTTPS/cookies `Secure` y comparte sesiones y límites de intentos mediante PostgreSQL, por lo que pueden atenderlos varios workers del mismo servicio. El blueprint usa planes gratuitos para facilitar la demostración. Según las condiciones actuales de Render, la base gratuita tiene 1 GB, expira 30 días después de su creación y, tras un período de gracia, se elimina; no ofrece backups. Revisa la documentación y los precios antes del despliegue y sube a un plan apropiado si necesitas conservar datos. No cambies el servicio a una base efímera para guardar estados que deban persistir.

Para otro proveedor, configura `DATABASE_URL` con una base PostgreSQL accesible, `COOKIE_SECURE=true`, las variables `DEMO_PASSWORD_*` antes del primer arranque y ejecuta `gunicorn --chdir src wsgi:app --bind 0.0.0.0:$PORT`. Configura el proxy HTTPS del proveedor y restringe su acceso de red a la base. Para desarrollo local, omite `DATABASE_URL` y se utilizará SQLite.

## Funcionalidad

- Cola de alertas sintéticas, filtros por estado/prioridad, antigüedad, SLA, volumen y excepciones.
- Workflow con asignación, reasignación, análisis, escalamiento, aprobación/devolución, cierre y reapertura.
- Las acciones efectivas registran actor, fecha UTC, motivo y referencia de evidencia sintética.
- Los roles se validan en el servidor. El auditor tiene acceso de solo lectura; los casos críticos requieren un revisor distinto al analista asignado. Los intentos bloqueados se auditan.
- La API mantiene las rutas consumidas por la interfaz: `/api/session`, `/api/login`, `/api/logout`, `/api/dashboard`, `/api/audit`, `/api/users`, `/api/alerts/{id}` y `/api/alerts/{id}/actions`.
- Plazos académicos de ejemplo en `src\backend\seed.py`: crítica 12 h, alta 5 d, media 3 d y baja 7 d.

## Controles y límites de seguridad

- Contraseñas con PBKDF2-HMAC-SHA256, sal aleatoria y 600 000 iteraciones. Las cuentas de una base anterior se migran al nuevo costo de hash en su próximo inicio de sesión correcto. Las respuestas de acceso no revelan si el usuario existe; el límite por IP y usuario se guarda en la base para que lo compartan los workers.
- Sesiones con token criptográficamente aleatorio; en la base solo se guarda su hash. Cookie `HttpOnly`, `SameSite=Strict`, `Secure` en despliegue, caducidad y revocación al cerrar sesión. Las sesiones de despliegue persisten entre procesos y reinicios hasta caducar o revocarse.
- Escrituras requieren `Origin` local y JSON, tienen un límite de tamaño y autorización por rol/estado en servidor. Las consultas SQL usan parámetros.
- El servidor de desarrollo se enlaza a `127.0.0.1`; en Render Gunicorn escucha en el puerto indicado por la plataforma detrás de su proxy HTTPS. CSP y encabezados HTTP reducen riesgos de contenido activo.

**El blueprint facilita un despliegue de demostración, no convierte el prototipo en apto para producción o datos reales.** Faltan SSO/MFA, recuperación segura de cuentas, política operativa de secretos, backups verificados, auditoría inmutable, alertas/monitoreo y revisión de seguridad independiente. Usa solo datos ficticios, protege las variables de entorno y revisa las cuotas y persistencia del proveedor. Un uso institucional requiere una revisión de seguridad y controles operativos adicionales.

## Pruebas

```powershell
python -m unittest discover -s tests -v
```

Las pruebas crean una base aislada y temporal; no cambian `src\data\alerts.sqlite3`.
