# Gestión de Boletas y Mantenimientos Técnicos

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
