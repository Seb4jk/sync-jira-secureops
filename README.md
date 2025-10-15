# API de Sincronización Wazuh-Jira

API robusta desarrollada en TypeScript y Express.js para sincronizar vulnerabilidades (CVEs) detectadas por Wazuh con tareas y subtareas en Jira.

## 🚀 Características

- ✅ **TypeScript** con tipado estricto
- ✅ **Express.js** con arquitectura modular y clean code
- ✅ **Autenticación JWT** con login y validación de tokens
- ✅ **Integración con Wazuh** para obtener CVEs
- ✅ **Integración con Jira** para crear tareas y subtareas
- ✅ **Logging** con Winston y Morgan
- ✅ **Manejo de errores** centralizado
- ✅ **CORS** configurable
- ✅ **Health checks** (liveness y readiness)
- ✅ **Variables de entorno** con dotenv

## 📁 Estructura del Proyecto

```
sync-jira-wazuh/
├── src/
│   ├── config/              # Configuración centralizada
│   │   └── index.ts
│   ├── controllers/         # Controladores (lógica de endpoints)
│   │   ├── auth.controller.ts
│   │   ├── health.controller.ts
│   │   └── vulnerabilities.controller.ts
│   ├── middlewares/         # Middlewares personalizados
│   │   ├── auth.middleware.ts
│   │   ├── error.middleware.ts
│   │   ├── logger.middleware.ts
│   │   └── validation.middleware.ts
│   ├── routes/              # Definición de rutas
│   │   ├── auth.routes.ts
│   │   ├── health.routes.ts
│   │   ├── vulnerabilities.routes.ts
│   │   └── index.ts
│   ├── services/            # Lógica de negocio e integraciones
│   │   ├── auth.service.ts
│   │   ├── jira.service.ts
│   │   └── wazuh.service.ts
│   ├── types/               # Tipos e interfaces TypeScript
│   │   └── index.ts
│   ├── utils/               # Utilidades y helpers
│   │   ├── logger.ts
│   │   └── response.ts
│   ├── app.ts               # Configuración de la app Express
│   └── server.ts            # Punto de entrada del servidor
├── .gitignore
├── package.json
├── tsconfig.json
└── README.md
```

## 🛠️ Instalación

### Requisitos Previos

- **Node.js** >= 16.x
- **npm** o **yarn**

### Pasos

1. **Clonar el repositorio**

```bash
git clone <repository-url>
cd sync-jira-wazuh
```

2. **Instalar dependencias**

```bash
npm install
```

3. **Configurar variables de entorno**

Crea un archivo `.env` en la raíz del proyecto (puedes copiar `.env.example` si existe):

```env
# Server Configuration
PORT=3000
NODE_ENV=development
API_VERSION=1.0.0

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=24h

# Wazuh API Configuration
WAZUH_API_URL=https://wazuh-api.example.com
WAZUH_API_USER=admin
WAZUH_API_PASSWORD=admin

# Jira API Configuration
JIRA_API_URL=https://your-domain.atlassian.net
JIRA_API_EMAIL=your-email@example.com
JIRA_API_TOKEN=your-jira-api-token
JIRA_PROJECT_KEY=VULN

# CORS Configuration
CORS_ORIGIN=*

# Logging
LOG_LEVEL=debug
```

4. **Ejecutar en desarrollo**

```bash
npm run dev
```

El servidor se iniciará en `http://localhost:3000`

5. **Compilar para producción**

```bash
npm run build
npm start
```

## 📡 Endpoints Disponibles

### Health Checks

#### `GET /health`
Verifica el estado general del API.

**Respuesta:**
```json
{
  "success": true,
  "message": "API saludable",
  "data": {
    "status": "ok",
    "version": "1.0.0",
    "environment": "development",
    "timestamp": "2024-10-14T12:00:00.000Z",
    "uptime": 123.45,
    "memory": {
      "total": "50 MB",
      "used": "30 MB"
    }
  }
}
```

#### `GET /health/ready`
Verifica si el servicio está listo para recibir tráfico.

#### `GET /health/live`
Verifica si el servicio está vivo.

---

### Autenticación

#### `POST /auth/login`
Inicia sesión y obtiene un token JWT.

**Body:**
```json
{
  "email": "admin@example.com",
  "password": "admin123"
}
```

**Respuesta:**
```json
{
  "success": true,
  "message": "Login exitoso",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": "24h",
    "user": {
      "id": "1",
      "email": "admin@example.com"
    }
  }
}
```

#### `GET /auth/validate`
Valida el token actual. **Requiere autenticación.**

**Headers:**
```
Authorization: Bearer <token>
```

#### `POST /auth/refresh`
Refresca el token JWT. **Requiere autenticación.**

#### `GET /auth/me`
Obtiene información del usuario autenticado. **Requiere autenticación.**

---

### Vulnerabilidades

#### `POST /vulnerabilities/sync`
Sincroniza CVEs de Wazuh con tareas de Jira. **Requiere autenticación.**

**Headers:**
```
Authorization: Bearer <token>
```

**Respuesta:**
```json
{
  "success": true,
  "message": "Sincronización completada exitosamente",
  "data": {
    "cvesProcessed": 3,
    "tasksCreated": 3,
    "subtasksCreated": 5,
    "errors": 0,
    "duration": 1234,
    "details": [
      {
        "cve": "CVE-2024-1234",
        "taskKey": "VULN-123",
        "subtasksCount": 2,
        "status": "success"
      }
    ]
  }
}
```

#### `GET /vulnerabilities/cves`
Obtiene la lista de CVEs desde Wazuh. **Requiere autenticación.**

#### `GET /vulnerabilities/cves/:cveId`
Obtiene detalles de un CVE específico. **Requiere autenticación.**

---

## 🔐 Autenticación

Todos los endpoints excepto `/health` y `/auth/login` requieren autenticación mediante JWT.

Para autenticarte:

1. Haz login en `/auth/login` con credenciales válidas
2. Obtén el token JWT de la respuesta
3. Incluye el token en el header `Authorization` de las siguientes peticiones:

```
Authorization: Bearer <tu-token-jwt>
```

### Credenciales de Demo

```
Email: admin@example.com
Password: admin123
```

> ⚠️ **Importante:** En producción, implementa un sistema de usuarios con contraseñas hasheadas (bcrypt) y almacenamiento en base de datos.

---

## 🧪 Pruebas con cURL

### Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

### Health Check
```bash
curl http://localhost:3000/health
```

### Sincronizar Vulnerabilidades
```bash
curl -X POST http://localhost:3000/vulnerabilities/sync \
  -H "Authorization: Bearer <tu-token>"
```

### Obtener CVEs
```bash
curl http://localhost:3000/vulnerabilities/cves \
  -H "Authorization: Bearer <tu-token>"
```

---

## 🔧 Configuración de Integración

### Wazuh

Para conectar con una instancia real de Wazuh:

1. Configura `WAZUH_API_URL` en el archivo `.env`
2. Proporciona credenciales válidas en `WAZUH_API_USER` y `WAZUH_API_PASSWORD`
3. Modifica `src/services/wazuh.service.ts` para hacer llamadas reales a la API de Wazuh

### Jira

Para conectar con Jira:

1. Crea un token de API en Jira: https://id.atlassian.com/manage/api-tokens
2. Configura las variables en `.env`:
   - `JIRA_API_URL`: URL de tu instancia (ej: https://tu-empresa.atlassian.net)
   - `JIRA_API_EMAIL`: Tu email de Jira
   - `JIRA_API_TOKEN`: El token generado
   - `JIRA_PROJECT_KEY`: Clave del proyecto donde se crearán las tareas
3. Descomenta las llamadas reales en `src/services/jira.service.ts`

---

## 📝 Desarrollo

### Scripts disponibles

```bash
npm run dev      # Inicia el servidor en modo desarrollo con hot-reload
npm run build    # Compila TypeScript a JavaScript
npm start        # Inicia el servidor en producción (requiere build)
npm run lint     # Ejecuta el linter (si está configurado)
npm run format   # Formatea el código con Prettier (si está configurado)
```

### Buenas Prácticas Implementadas

- ✅ **Clean Code**: Separación de responsabilidades, nombres descriptivos
- ✅ **Tipado estricto**: TypeScript con configuración strict
- ✅ **Manejo de errores**: Middleware centralizado y errores personalizados
- ✅ **Logging estructurado**: Winston con diferentes niveles
- ✅ **Async handlers**: Wrapper para evitar try-catch repetitivos
- ✅ **Validación de datos**: Middlewares de validación
- ✅ **Respuestas consistentes**: Utilidades para formatear respuestas

---

## 🚀 Despliegue en Producción

### Consideraciones

1. **Variables de entorno**: Asegúrate de configurar todas las variables en producción
2. **JWT_SECRET**: Usa un secreto fuerte y único
3. **HTTPS**: Habilita HTTPS en producción
4. **Rate limiting**: Considera agregar rate limiting (ej: express-rate-limit)
5. **Helmet**: Agrega helmet.js para seguridad HTTP
6. **Monitoreo**: Implementa monitoreo y alertas
7. **Logs**: Configura rotación de logs en producción

### Ejemplo de despliegue con PM2

```bash
npm install -g pm2
npm run build
pm2 start dist/server.js --name "sync-jira-wazuh"
```

---

## 🐛 Solución de Problemas

### El servidor no inicia
- Verifica que el puerto no esté en uso
- Revisa que todas las dependencias estén instaladas
- Verifica que el archivo `.env` esté configurado

### Errores de autenticación
- Verifica que el token JWT sea válido y no haya expirado
- Asegúrate de incluir el header `Authorization: Bearer <token>`

### Errores de integración
- Verifica las credenciales de Wazuh y Jira en `.env`
- Revisa los logs para más detalles del error

---

## 📄 Licencia

ISC

---

## 👨‍💻 Autor

Desarrollado como proyecto de sincronización de vulnerabilidades empresariales.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Haz un fork del proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

---

## 📞 Soporte

Para soporte y preguntas, por favor abre un issue en el repositorio.

