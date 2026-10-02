# Faro — tablero de gestión de alertas

Prototipo académico basado en `Proyecto-6_Gestion-de-alertas.pdf`. Presenta únicamente usuarios, alertas y referencias de evidencia sintéticos; no integra plataformas ni acepta archivos reales.

## Ejecutar localmente

Requiere Python 3.10 o superior y no instala dependencias externas. Desde la carpeta del proyecto:

```powershell
python src\server.py
```

Abra <http://127.0.0.1:8765/>. La primera vez, el servidor crea la base local y muestra cinco cuentas ficticias con contraseñas aleatorias en esa consola. Cópielas para la demo: las contraseñas no se guardan en texto plano ni se vuelven a mostrar. Para regenerar los datos y las credenciales, detenga el servidor y elimine el archivo específico `src\data\alerts.sqlite3` (y sus archivos `-wal`/`-shm`, si existen); al iniciar de nuevo se recreará la base sintética. Puede cambiar el puerto con la variable de entorno `PORT`.

## Alcance funcional

- Cola con filtros de estado/prioridad, prioridad visual, antigüedad, SLA, excepciones y métricas de operación.
- Transiciones de estados mediante acciones autenticadas: asignar/reasignar, analizar, escalar, aprobar/devolver, cerrar y reabrir. Toda acción efectiva pide motivo y referencia de evidencia sintética.
- La API comprueba rol, estado y segregación; un analista no puede cerrar su caso crítico y un revisor distinto debe aprobarlo. Cada intento bloqueado se agrega a la bitácora.
- Vista de auditoría de solo lectura (rol Auditoría) para consultar excepciones y vencimientos.
- Plazos académicos editables en `src\server.py`: crítica 12 h, alta 5 d, media 3 d y baja 7 d. Los datos de muestra producen 20 abiertas, 3 vencidas, 1 reabierta y 2 excepciones.

## Controles de seguridad del prototipo

Las contraseñas se derivan con PBKDF2-HMAC-SHA256 y sal aleatoria; las sesiones usan tokens aleatorios en cookies `HttpOnly`/`SameSite=Strict`, con expiración de ocho horas. Se limitan los intentos de acceso, se valida el origen de solicitudes de escritura y se aplican CSP y encabezados contra contenido activo. Las consultas SQL usan parámetros, las acciones se autorizan en el servidor y la UI inserta valores dinámicos como texto.

**No es un sistema de producción ni demuestra seguridad institucional.** Se enlaza solo a `127.0.0.1`; no tiene TLS, gestión institucional de identidades/MFA, controles de acceso por organización, cifrado en reposo, copias de seguridad, administración de usuarios, monitoreo central ni protección contra manipulación directa del archivo SQLite o del host local. La base y la bitácora local son demostrativas y no tienen garantías de inmutabilidad. Mantenga los datos sintéticos y no exponga el puerto en una red.

## Pruebas

```powershell
python -m unittest discover -s tests -v
```
