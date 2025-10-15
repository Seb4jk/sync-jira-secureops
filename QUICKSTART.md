# 🚀 Inicio Rápido - 3 Pasos

## ⚡ Ejecutar en 3 Comandos

```bash
# 1. Instalar dependencias
npm install

# 2. Configurar variables de entorno (copia y edita)
cp env.example.txt .env

# 3. Ejecutar
npm run dev
```

El servidor estará disponible en: **http://localhost:3000**

---

## ✅ Verificar que Funciona

### Opción 1: Desde el Navegador

Abre en tu navegador:
```
http://localhost:3000/health
```

### Opción 2: Desde la Terminal

**PowerShell (Windows):**
```powershell
Invoke-RestMethod http://localhost:3000/health
```

**Bash (Linux/Mac):**
```bash
curl http://localhost:3000/health
```

Si ves un JSON con `"status": "ok"`, ¡todo funciona! ✅

---

## 🔑 Credenciales de Demo

Para hacer login:
```
Email: admin@example.com
Password: admin123
```

---

## 📝 Ejemplo de Uso Completo

### 1. Hacer Login (PowerShell)

```powershell
$loginBody = @{
    email = "admin@example.com"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:3000/auth/login" `
    -Method Post `
    -ContentType "application/json" `
    -Body $loginBody

$token = $response.data.token
Write-Host "Token obtenido: $token"
```

### 2. Sincronizar Vulnerabilidades (PowerShell)

```powershell
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$syncResult = Invoke-RestMethod -Uri "http://localhost:3000/vulnerabilities/sync" `
    -Method Post `
    -Headers $headers

Write-Host "CVEs procesados: $($syncResult.data.cvesProcessed)"
Write-Host "Tareas creadas: $($syncResult.data.tasksCreated)"
Write-Host "Subtareas creadas: $($syncResult.data.subtasksCreated)"
```

### Alternativa con Bash

```bash
# 1. Login y obtener token
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}' \
  | jq -r '.data.token')

echo "Token: $TOKEN"

# 2. Sincronizar vulnerabilidades
curl -X POST http://localhost:3000/vulnerabilities/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

---

## 📚 Próximos Pasos

1. ✅ **Lee el README.md** → Documentación completa
2. ✅ **Lee SETUP.md** → Guía de instalación detallada
3. ✅ **Lee EJEMPLOS_USO.md** → Ejemplos avanzados
4. ✅ **Importa POSTMAN_COLLECTION.json** → Prueba todos los endpoints

---

## 🛠️ Solución Rápida de Problemas

### Error: Puerto 3000 en uso

**Windows:**
```powershell
# Ver qué proceso usa el puerto
netstat -ano | findstr :3000

# Matar el proceso (reemplaza <PID>)
taskkill /PID <PID> /F
```

**Linux/Mac:**
```bash
# Ver y matar el proceso
lsof -ti:3000 | xargs kill
```

### Error: No encuentra módulos

```bash
rm -rf node_modules package-lock.json
npm install
```

### Error: Variables de entorno no definidas

Asegúrate de crear el archivo `.env`:
```bash
cp env.example.txt .env
```

Y edítalo con tu configuración.

---

## 🎯 Endpoints Principales

| Endpoint | Método | Autenticación | Descripción |
|----------|--------|---------------|-------------|
| `/health` | GET | No | Estado del servidor |
| `/auth/login` | POST | No | Login y obtener token |
| `/vulnerabilities/sync` | POST | Sí | Sincronizar CVEs |
| `/vulnerabilities/cves` | GET | Sí | Listar todos los CVEs |

---

## 🎉 ¡Listo!

Ahora tienes una API completamente funcional para sincronizar vulnerabilidades de Wazuh con Jira.

**¿Preguntas?** Revisa el README.md o los archivos de documentación.

