# Guía de Instalación Rápida

## 📋 Prerrequisitos

Antes de comenzar, asegúrate de tener instalado:

- **Node.js** >= 16.x (recomendado v18 o superior)
- **npm** >= 8.x o **yarn** >= 1.22.x
- **Git** (opcional, para clonar el repositorio)

## 🚀 Instalación Paso a Paso

### 1. Instalar Dependencias

```bash
npm install
```

Este comando instalará todas las dependencias necesarias:
- Express.js (framework web)
- TypeScript (lenguaje)
- JWT (autenticación)
- Axios (cliente HTTP)
- Winston y Morgan (logging)
- CORS (middleware)
- Y todas las definiciones de tipos necesarias

### 2. Configurar Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido (puedes copiar desde `env.example.txt`):

```bash
# Copia el archivo de ejemplo
cp env.example.txt .env
```

O crea el archivo `.env` manualmente con este contenido mínimo:

```env
PORT=3000
NODE_ENV=development
JWT_SECRET=mi-secreto-super-seguro-cambiar-en-produccion
```

### 3. Ejecutar en Modo Desarrollo

```bash
npm run dev
```

El servidor se iniciará en `http://localhost:3000` con hot-reload activado.

### 4. Verificar que Funciona

Abre tu navegador o usa curl para verificar el health endpoint:

```bash
curl http://localhost:3000/health
```

Deberías recibir una respuesta JSON similar a:

```json
{
  "success": true,
  "message": "API saludable",
  "data": {
    "status": "ok",
    "version": "1.0.0",
    "environment": "development",
    "timestamp": "2024-10-14T...",
    "uptime": 12.34,
    "memory": {
      "total": "50 MB",
      "used": "30 MB"
    }
  }
}
```

## 🧪 Probar la API

### 1. Hacer Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "admin123"
  }'
```

Esto te devolverá un token JWT. Copia el valor del campo `token`.

### 2. Sincronizar Vulnerabilidades

Usa el token obtenido en el paso anterior:

```bash
curl -X POST http://localhost:3000/vulnerabilities/sync \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json"
```

### 3. Obtener CVEs

```bash
curl http://localhost:3000/vulnerabilities/cves \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

## 🏗️ Compilar para Producción

### Compilar TypeScript

```bash
npm run build
```

Esto generará los archivos JavaScript en la carpeta `dist/`.

### Ejecutar en Producción

```bash
npm start
```

O usando PM2 (recomendado):

```bash
npm install -g pm2
pm2 start dist/server.js --name "sync-jira-wazuh"
pm2 save
pm2 startup
```

## 🔧 Configuración Avanzada

### Conectar con Wazuh Real

Edita tu archivo `.env`:

```env
WAZUH_API_URL=https://tu-wazuh-server.com:55000
WAZUH_API_USER=tu-usuario
WAZUH_API_PASSWORD=tu-password
```

### Conectar con Jira Real

1. Genera un API Token en Jira: https://id.atlassian.com/manage/api-tokens
2. Edita tu archivo `.env`:

```env
JIRA_API_URL=https://tu-empresa.atlassian.net
JIRA_API_EMAIL=tu-email@empresa.com
JIRA_API_TOKEN=tu-token-generado
JIRA_PROJECT_KEY=VULN
```

3. Modifica los servicios para usar las llamadas reales (descomenta las líneas en `src/services/wazuh.service.ts` y `src/services/jira.service.ts`).

## 📊 Scripts Disponibles

| Script | Descripción |
|--------|-------------|
| `npm run dev` | Inicia el servidor en modo desarrollo con hot-reload |
| `npm run build` | Compila TypeScript a JavaScript |
| `npm start` | Ejecuta el servidor compilado |
| `npm run lint` | Ejecuta el linter |
| `npm run format` | Formatea el código con Prettier |

## ❓ Troubleshooting

### El servidor no inicia

**Error: Puerto en uso**
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:3000 | xargs kill
```

**Error: Módulos no encontrados**
```bash
rm -rf node_modules package-lock.json
npm install
```

### Errores de TypeScript

Si ves errores de tipos no encontrados:

```bash
npm install --save-dev @types/node @types/express
```

### El token JWT expira muy rápido

Edita el archivo `.env` y cambia:

```env
JWT_EXPIRES_IN=7d  # 7 días
# o
JWT_EXPIRES_IN=30d  # 30 días
```

## 🎯 Próximos Pasos

1. ✅ Instala y ejecuta la API
2. ✅ Prueba los endpoints con curl o Postman
3. ✅ Configura las integraciones con Wazuh y Jira
4. ✅ Personaliza según tus necesidades
5. ✅ Despliega en producción

## 📞 Soporte

Si tienes problemas, revisa:
1. Los logs en la consola (modo desarrollo)
2. El archivo `logs/error.log` (modo producción)
3. La documentación completa en `README.md`

¡Listo! Ahora tienes la API completamente funcional. 🎉

