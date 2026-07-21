#!/usr/bin/env python3
from __future__ import annotations

import base64
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

if len(sys.argv) != 3:
    raise SystemExit('Uso: sanitize_public_copy.py <origen> <destino>')

source = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
if not source.is_dir():
    raise SystemExit(f'No existe el origen: {source}')

shutil.rmtree(root, ignore_errors=True)
shutil.copytree(source, root, ignore=shutil.ignore_patterns('.git', 'node_modules', 'dist', 'build', 'coverage'))

blocked_dirs = {
    '.git', '.idea', '.vscode', 'node_modules', 'dist', 'build', 'coverage',
    'uploads', 'exports', 'backups', 'backup', 'logs', 'tmp', 'temp', '.cache',
    '.turbo', '.next', '__pycache__'
}
blocked_suffixes = {
    '.pem', '.key', '.p12', '.pfx', '.crt', '.cer', '.jks', '.keystore',
    '.sqlite', '.sqlite3', '.db', '.bak', '.log', '.xlsx', '.xls', '.csv',
    '.zip', '.7z', '.rar'
}
sensitive_filename_parts = {
    'service-account', 'service_account', 'credentials', 'credential',
    'private-key', 'private_key', 'oauth-client', 'oauth_client',
    'database-dump', 'database_dump', 'secret-backup'
}

for path in sorted(root.rglob('*'), key=lambda p: len(p.parts), reverse=True):
    name = path.name.lower()
    if path.is_dir() and name in blocked_dirs:
        shutil.rmtree(path, ignore_errors=True)
    elif path.is_file():
        if path.suffix.lower() in blocked_suffixes:
            path.unlink(missing_ok=True)
        elif name.startswith('.env') and name not in {'.env.example', '.env.sample'}:
            path.unlink(missing_ok=True)
        elif any(part in name for part in sensitive_filename_parts):
            path.unlink(missing_ok=True)

# Evita copiar automatizaciones de despliegue ligadas al entorno original.
shutil.rmtree(root / '.github' / 'workflows', ignore_errors=True)

replacements = {
    'Digital Management Systems, S.A.': 'Empresa de Servicios Técnicos',
    'Digital Management Systems S.A.': 'Empresa de Servicios Técnicos',
    'Digital Management Systems': 'Empresa de Servicios Técnicos',
    'DMS Boletas': 'Gestión de Boletas',
    'DMS_Boletas': 'Gestion_Boletas',
    'dms-boletas': 'gestion-boletas-mantenimientos',
    'Andrick Almengor Quirós': 'Usuario Administrador',
    'Andrick Almengor Quiros': 'Usuario Administrador',
    'Andrick Almengor': 'Usuario Administrador',
    'Andri Almengor': 'Usuario Administrador',
    'Yehuda Carmona': 'Supervisor Técnico',
    'Roy Umaña': 'Gerencia Administrativa',
    'Alejandra Umaña': 'Asistencia Administrativa',
    'Raúl Mayorga': 'Responsable Técnico',
    'Raul Mayorga': 'Responsable Técnico',
    'Francisco Murillo': 'Técnico de ejemplo',
    'Dixon Mora': 'Técnico de ejemplo',
    'Yasdani Valdivia': 'Técnico de ejemplo',
    'Freddy Fernández': 'Técnico de ejemplo',
    'Freddy Fernandez': 'Técnico de ejemplo',
    'Jorge Espinoza': 'Técnico de ejemplo',
    'Asamblea Legislativa de Costa Rica': 'Cliente de ejemplo',
    'Asamblea Legislativa': 'Cliente de ejemplo',
    'Banco Central de Costa Rica': 'Cliente de ejemplo',
    'Banco Central': 'Cliente de ejemplo',
    'Banco de Costa Rica': 'Cliente de ejemplo',
    'Promerica': 'Cliente de ejemplo',
    'Acueductos y Alcantarillados': 'Cliente de ejemplo',
    'CCSS': 'Cliente de ejemplo',
    'Instituto Costarricense de Electricidad': 'Cliente de ejemplo',
    'Instituto Nacional de Seguros': 'Cliente de ejemplo',
    'Ministerio de Hacienda': 'Cliente de ejemplo',
    'Ministerio de Salud': 'Cliente de ejemplo',
    'Amazon Support Services': 'Cliente de ejemplo',
    'Boston Scientific': 'Cliente de ejemplo',
    'ICU Medical Costa Rica Ltd': 'Cliente de ejemplo',
    'Junta Administrativa del Registro Nacional': 'Cliente de ejemplo',
    'Azucarera El Viejo': 'Cliente de ejemplo',
    'Abbott Medical': 'Cliente de ejemplo',
    'CBRE': 'Cliente de ejemplo',
    'ADT': 'Cliente de ejemplo',
}

safe_hosts = {
    'localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'example.org',
    'example.invalid', 'github.com', 'api.github.com', 'raw.githubusercontent.com',
    'registry.npmjs.org', 'npmjs.com', 'nodejs.org', 'react.dev', 'vite.dev',
    'vitejs.dev', 'developer.mozilla.org', 'developers.google.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'www.gstatic.com',
    'cdnjs.cloudflare.com', 'unpkg.com', 'cdn.jsdelivr.net', 'schema.org'
}

url_pattern = re.compile(r'https?://[^\s\"\'<>`)}\]]+')
email_pattern = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
phone_pattern = re.compile(r'(?<!\d)(?:\+?506[\s-]?\d{4}[\s-]?\d{4}|\d{4}[\s-]\d{4})(?!\d)')
ipv4_pattern = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
private_key_pattern = re.compile(
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S
)


def sanitize_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    trimmed = raw.rstrip('.,;:')
    punctuation = raw[len(trimmed):]
    try:
        host = (urlparse(trimmed).hostname or '').lower()
    except Exception:
        return 'https://example.invalid' + punctuation
    if host in safe_hosts or host.endswith('.npmjs.org'):
        return trimmed + punctuation
    if host in {'script.google.com', 'docs.google.com', 'drive.google.com', 'chat.googleapis.com'}:
        return 'https://example.invalid/configure-google-service' + punctuation
    if 'render.com' in host or 'onrender.com' in host:
        return 'https://example.invalid/configure-backend' + punctuation
    return 'https://example.invalid/configure-service' + punctuation


def sanitize_ip(match: re.Match[str]) -> str:
    value = match.group(0)
    if value in {'127.0.0.1', '0.0.0.0'}:
        return value
    octets = value.split('.')
    if any(int(part) > 255 for part in octets):
        return value
    return '192.0.2.10'


def sanitize_text(text: str) -> str:
    for original, replacement in replacements.items():
        text = re.sub(re.escape(original), replacement, text, flags=re.I)
    # Mantiene identificadores válidos cuando la sigla aparece en código.
    text = re.sub(r'\bDMS\b', 'GT', text)
    text = re.sub(r'\bdms\b', 'gt', text)
    text = private_key_pattern.sub('PRIVATE_KEY_REMOVED', text)
    text = email_pattern.sub('usuario@ejemplo.com', text)
    text = phone_pattern.sub('0000-0000', text)
    text = ipv4_pattern.sub(sanitize_ip, text)
    text = url_pattern.sub(sanitize_url, text)
    text = re.sub(
        r'(?im)^(\s*(?:(?:export\s+)?(?:const|let|var)\s+)?[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|WEBHOOK_URL|SPREADSHEET_ID|FOLDER_ID|TEMPLATE_ID|DEPLOYMENT_ID)[A-Z0-9_]*\s*[:=]\s*)([\"\'])(.*?)(\2)(\s*[,;]?)$',
        lambda m: f'{m.group(1)}{m.group(2)}CONFIGURE_ME{m.group(2)}{m.group(5)}',
        text,
    )
    return text


placeholder_png = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII='
)
placeholder_svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
<rect width="512" height="512" rx="96" fill="#9f151d"/>
<path d="M128 144h256v224H128z" fill="#fff"/>
<path d="M176 208h160M176 256h160M176 304h104" stroke="#9f151d" stroke-width="24" stroke-linecap="round"/>
</svg>'''
image_suffixes = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.svg', '.ico'}

for path in sorted(root.rglob('*')):
    if not path.is_file():
        continue
    suffix = path.suffix.lower()
    if suffix in image_suffixes:
        if suffix == '.svg':
            path.write_text(placeholder_svg, encoding='utf-8')
        else:
            path.write_bytes(placeholder_png)
        continue
    try:
        if path.stat().st_size > 5_000_000:
            continue
        raw = path.read_bytes()
        if b'\x00' in raw[:4096]:
            continue
        text = raw.decode('utf-8')
    except (UnicodeDecodeError, OSError):
        continue
    cleaned = sanitize_text(text)
    if cleaned != text:
        path.write_text(cleaned, encoding='utf-8')

(root / '.env.example').write_text('''# Copie este archivo como .env y complete los valores en un entorno privado.
NODE_ENV=development
PORT=3000
FRONTEND_ORIGIN=http://localhost:5173
GOOGLE_SPREADSHEET_ID=CONFIGURE_ME
GOOGLE_DRIVE_ROOT_FOLDER_ID=CONFIGURE_ME
GOOGLE_SERVICE_ACCOUNT_EMAIL=usuario@ejemplo.com
GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY=CONFIGURE_ME
APPS_SCRIPT_WEB_APP_URL=https://example.invalid/configure-google-service
SESSION_SECRET=CONFIGURE_A_LONG_RANDOM_SECRET
GEMINI_API_KEY=CONFIGURE_ME
''', encoding='utf-8')

(root / 'README.md').write_text('''# Gestión de Boletas y Mantenimientos Técnicos

Aplicación web de referencia para administrar boletas de servicio, mantenimientos, dispositivos, evidencias, firmas, documentos y métricas operativas.

## Tecnologías

- React y Vite
- Node.js y Express
- Google Sheets y Google Drive
- Google Apps Script
- PWA con soporte sin conexión

## Seguridad

Este repositorio es una versión pública sanitizada. No contiene credenciales, identificadores reales de Google, webhooks, datos de clientes, nombres del personal, firmas, fotografías ni exportaciones del sistema operativo.

Configure sus propios recursos usando `.env.example`. Nunca publique el archivo `.env` ni llaves privadas.

## Instalación

```bash
npm install
cd backend && npm install
```

Ejecute el frontend y el backend con los scripts definidos en sus respectivos `package.json`.

## Funciones principales

- Gestión de boletas pendientes y finalizadas.
- Registro de mantenimientos y dispositivos.
- Evidencias y firmas digitales.
- Documentos mediante integraciones configurables.
- Roles, permisos, auditoría y métricas.
- Sincronización y recuperación de formularios.
''', encoding='utf-8')

(root / 'SECURITY.md').write_text('''# Seguridad

- No publique archivos `.env`, llaves privadas, cuentas de servicio o tokens.
- Use secretos del proveedor de despliegue para las credenciales.
- Rote inmediatamente cualquier credencial expuesta.
- Restrinja los permisos de Drive y Sheets al mínimo necesario.
- Mantenga actualizadas las dependencias.
''', encoding='utf-8')

(root / 'SANITIZATION_REPORT.md').write_text('''# Informe de sanitización

La copia pública se creó desde una instantánea del código y sin copiar el historial Git del sistema operativo.

Se eliminaron o reemplazaron la marca de la empresa original, nombres de personal y clientes, correos, teléfonos, direcciones IP, enlaces privados, identificadores de Google, webhooks, credenciales, certificados, bases de datos, exportaciones, registros, logotipos, firmas, fotografías y flujos de despliegue del entorno original.

Antes de desplegar esta versión se deben crear recursos nuevos y completar las variables de entorno.
''', encoding='utf-8')

workflow_dir = root / '.github' / 'workflows'
workflow_dir.mkdir(parents=True, exist_ok=True)
(workflow_dir / 'validate.yml').write_text('''name: Validar aplicación

on:
  push:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npm run build
      - run: npm ci
        working-directory: backend
      - run: npm run check --if-present
        working-directory: backend
''', encoding='utf-8')

gitignore = root / '.gitignore'
existing = gitignore.read_text(encoding='utf-8') if gitignore.exists() else ''
gitignore.write_text(existing.rstrip() + '''

# Información privada
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
*.jks
*.keystore
*.sqlite
*.sqlite3
*.db
*.log
/uploads/
/exports/
/backups/
''', encoding='utf-8')
