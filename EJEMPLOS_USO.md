# Ejemplos de Uso - API Sync Jira-Wazuh

Esta guía contiene ejemplos prácticos de cómo usar la API en diferentes escenarios.

## 📋 Tabla de Contenidos

1. [Flujo Básico Completo](#flujo-básico-completo)
2. [Autenticación](#autenticación)
3. [Sincronización de Vulnerabilidades](#sincronización-de-vulnerabilidades)
4. [Consulta de CVEs](#consulta-de-cves)
5. [Ejemplos con JavaScript/TypeScript](#ejemplos-con-javascripttypescript)
6. [Ejemplos con Python](#ejemplos-con-python)
7. [Manejo de Errores](#manejo-de-errores)

---

## 🚀 Flujo Básico Completo

### 1. Verificar Estado del Servidor

```bash
curl http://localhost:3000/health
```

### 2. Hacer Login y Obtener Token

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "admin123"
  }'
```

**Respuesta:**
```json
{
  "success": true,
  "message": "Login exitoso",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUuY29tIiwiaWF0IjoxNjk3MjE1MjAwLCJleHAiOjE2OTczMDE2MDB9.xyz",
    "expiresIn": "24h",
    "user": {
      "id": "1",
      "email": "admin@example.com"
    }
  }
}
```

### 3. Sincronizar Vulnerabilidades

```bash
export TOKEN="tu-token-aqui"

curl -X POST http://localhost:3000/vulnerabilities/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
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
      },
      {
        "cve": "CVE-2024-5678",
        "taskKey": "VULN-124",
        "subtasksCount": 1,
        "status": "success"
      },
      {
        "cve": "CVE-2024-9012",
        "taskKey": "VULN-125",
        "subtasksCount": 2,
        "status": "success"
      }
    ]
  }
}
```

---

## 🔐 Autenticación

### Login

**PowerShell (Windows):**
```powershell
$body = @{
    email = "admin@example.com"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:3000/auth/login" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body

$token = $response.data.token
Write-Host "Token: $token"
```

**Bash (Linux/Mac):**
```bash
response=$(curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}')

token=$(echo $response | jq -r '.data.token')
echo "Token: $token"
```

### Validar Token

```bash
curl http://localhost:3000/auth/validate \
  -H "Authorization: Bearer $TOKEN"
```

### Refrescar Token

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Authorization: Bearer $TOKEN"
```

### Obtener Usuario Actual

```bash
curl http://localhost:3000/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🔄 Sincronización de Vulnerabilidades

### Sincronizar y Procesar CVEs

```bash
curl -X POST http://localhost:3000/vulnerabilities/sync \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -v
```

### Interpretación de la Respuesta

La respuesta contiene:
- **cvesProcessed**: Número total de CVEs procesados
- **tasksCreated**: Tareas creadas en Jira
- **subtasksCreated**: Subtareas creadas (una por servidor afectado)
- **errors**: Número de errores encontrados
- **duration**: Tiempo de ejecución en milisegundos
- **details**: Array con detalles de cada CVE procesado

---

## 📊 Consulta de CVEs

### Obtener Todos los CVEs

```bash
curl http://localhost:3000/vulnerabilities/cves \
  -H "Authorization: Bearer $TOKEN"
```

**Respuesta:**
```json
{
  "success": true,
  "message": "CVEs obtenidos exitosamente",
  "data": {
    "count": 3,
    "cves": [
      {
        "id": "1",
        "cve": "CVE-2024-1234",
        "title": "SQL Injection en Apache Struts",
        "severity": "Critical",
        "cvss": 9.8,
        "description": "Vulnerabilidad crítica...",
        "affectedServers": [...]
      }
    ]
  }
}
```

### Obtener Detalles de un CVE Específico

```bash
curl http://localhost:3000/vulnerabilities/cves/CVE-2024-1234 \
  -H "Authorization: Bearer $TOKEN"
```

**Respuesta:**
```json
{
  "success": true,
  "message": "Detalles del CVE obtenidos",
  "data": {
    "id": "1",
    "cve": "CVE-2024-1234",
    "title": "SQL Injection en Apache Struts",
    "severity": "Critical",
    "cvss": 9.8,
    "description": "Vulnerabilidad crítica de inyección SQL...",
    "affectedServers": [
      {
        "id": "srv-001",
        "name": "Web Server 01",
        "hostname": "web01.example.com",
        "ip": "192.168.1.10",
        "os": "Ubuntu 22.04 LTS",
        "package": "apache-struts",
        "version": "2.5.30"
      }
    ],
    "published": "2024-01-15T00:00:00Z",
    "modified": "2024-01-20T00:00:00Z"
  }
}
```

---

## 💻 Ejemplos con JavaScript/TypeScript

### Cliente Node.js con Axios

```javascript
import axios from 'axios';

const API_URL = 'http://localhost:3000';
let authToken = '';

// Función de login
async function login() {
  try {
    const response = await axios.post(`${API_URL}/auth/login`, {
      email: 'admin@example.com',
      password: 'admin123'
    });
    
    authToken = response.data.data.token;
    console.log('Login exitoso, token:', authToken);
    return authToken;
  } catch (error) {
    console.error('Error en login:', error.response?.data || error.message);
    throw error;
  }
}

// Función para sincronizar vulnerabilidades
async function syncVulnerabilities() {
  try {
    const response = await axios.post(
      `${API_URL}/vulnerabilities/sync`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      }
    );
    
    console.log('Sincronización completada:');
    console.log(`- CVEs procesados: ${response.data.data.cvesProcessed}`);
    console.log(`- Tareas creadas: ${response.data.data.tasksCreated}`);
    console.log(`- Subtareas creadas: ${response.data.data.subtasksCreated}`);
    
    return response.data.data;
  } catch (error) {
    console.error('Error en sincronización:', error.response?.data || error.message);
    throw error;
  }
}

// Función para obtener CVEs
async function getCVEs() {
  try {
    const response = await axios.get(`${API_URL}/vulnerabilities/cves`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    console.log(`Total de CVEs: ${response.data.data.count}`);
    return response.data.data.cves;
  } catch (error) {
    console.error('Error al obtener CVEs:', error.response?.data || error.message);
    throw error;
  }
}

// Flujo completo
async function main() {
  try {
    // 1. Login
    await login();
    
    // 2. Sincronizar vulnerabilidades
    await syncVulnerabilities();
    
    // 3. Obtener lista de CVEs
    const cves = await getCVEs();
    
    // 4. Mostrar información
    cves.forEach(cve => {
      console.log(`\n${cve.cve} - ${cve.title}`);
      console.log(`  Severidad: ${cve.severity} (CVSS: ${cve.cvss})`);
      console.log(`  Servidores afectados: ${cve.affectedServers.length}`);
    });
    
  } catch (error) {
    console.error('Error en el flujo:', error);
  }
}

// Ejecutar
main();
```

---

## 🐍 Ejemplos con Python

### Cliente Python con requests

```python
import requests
import json

API_URL = 'http://localhost:3000'
auth_token = None

def login():
    """Realizar login y obtener token"""
    global auth_token
    
    response = requests.post(
        f'{API_URL}/auth/login',
        json={
            'email': 'admin@example.com',
            'password': 'admin123'
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        auth_token = data['data']['token']
        print(f'Login exitoso, token: {auth_token[:20]}...')
        return auth_token
    else:
        raise Exception(f'Error en login: {response.text}')

def sync_vulnerabilities():
    """Sincronizar vulnerabilidades"""
    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.post(
        f'{API_URL}/vulnerabilities/sync',
        headers=headers
    )
    
    if response.status_code == 200:
        data = response.json()['data']
        print('\nSincronización completada:')
        print(f"  - CVEs procesados: {data['cvesProcessed']}")
        print(f"  - Tareas creadas: {data['tasksCreated']}")
        print(f"  - Subtareas creadas: {data['subtasksCreated']}")
        print(f"  - Duración: {data['duration']}ms")
        return data
    else:
        raise Exception(f'Error en sincronización: {response.text}')

def get_cves():
    """Obtener lista de CVEs"""
    headers = {
        'Authorization': f'Bearer {auth_token}'
    }
    
    response = requests.get(
        f'{API_URL}/vulnerabilities/cves',
        headers=headers
    )
    
    if response.status_code == 200:
        data = response.json()['data']
        print(f"\nTotal de CVEs: {data['count']}")
        return data['cves']
    else:
        raise Exception(f'Error al obtener CVEs: {response.text}')

def main():
    """Flujo principal"""
    try:
        # 1. Login
        login()
        
        # 2. Sincronizar
        sync_vulnerabilities()
        
        # 3. Obtener CVEs
        cves = get_cves()
        
        # 4. Mostrar información
        print("\n" + "="*60)
        print("CVEs Encontrados:")
        print("="*60)
        
        for cve in cves:
            print(f"\n{cve['cve']} - {cve['title']}")
            print(f"  Severidad: {cve['severity']} (CVSS: {cve['cvss']})")
            print(f"  Servidores afectados: {len(cve['affectedServers'])}")
            
            for server in cve['affectedServers']:
                print(f"    - {server['name']} ({server['ip']})")
        
    except Exception as e:
        print(f'Error: {e}')

if __name__ == '__main__':
    main()
```

---

## ⚠️ Manejo de Errores

### Error 401 - No autenticado

```json
{
  "success": false,
  "message": "Token de autenticación no proporcionado",
  "error": "No token provided",
  "timestamp": "2024-10-14T12:00:00.000Z"
}
```

**Solución:** Incluir el header `Authorization: Bearer <token>`

### Error 403 - Token inválido

```json
{
  "success": false,
  "message": "Token inválido o expirado",
  "error": "jwt expired",
  "timestamp": "2024-10-14T12:00:00.000Z"
}
```

**Solución:** Hacer login nuevamente o refrescar el token

### Error 404 - Ruta no encontrada

```json
{
  "success": false,
  "message": "Ruta no encontrada: /api/wrong-endpoint",
  "timestamp": "2024-10-14T12:00:00.000Z"
}
```

**Solución:** Verificar la URL del endpoint

### Error 500 - Error del servidor

```json
{
  "success": false,
  "message": "Error al obtener vulnerabilidades de Wazuh",
  "error": "Connection refused",
  "timestamp": "2024-10-14T12:00:00.000Z"
}
```

**Solución:** Verificar que los servicios externos (Wazuh, Jira) estén accesibles

---

## 📝 Notas Adicionales

### Postman Collection

Importa el archivo `POSTMAN_COLLECTION.json` en Postman para tener todos los endpoints preconfigurados.

### Variables de Entorno

Para cambiar entre desarrollo y producción:

```bash
# Desarrollo
export NODE_ENV=development
npm run dev

# Producción
export NODE_ENV=production
npm start
```

### Logs

Los logs se encuentran en:
- **Consola**: En modo desarrollo
- **Archivo**: `logs/combined.log` y `logs/error.log` en producción

---

## 🎯 Casos de Uso Comunes

### 1. Sincronización Automática Programada

**Linux/Mac (crontab):**
```bash
# Ejecutar sincronización cada hora
0 * * * * curl -X POST http://localhost:3000/vulnerabilities/sync -H "Authorization: Bearer TOKEN"
```

**Windows (Task Scheduler):**
```powershell
# Script PowerShell para sincronización
$token = "tu-token"
Invoke-RestMethod -Uri "http://localhost:3000/vulnerabilities/sync" `
    -Method Post `
    -Headers @{"Authorization"="Bearer $token"}
```

### 2. Notificaciones por Email

Puedes extender el servicio para enviar notificaciones:

```javascript
// Después de sincronizar
const summary = await syncVulnerabilities();
if (summary.cvesProcessed > 0) {
  await sendEmailNotification(summary);
}
```

### 3. Dashboard en Tiempo Real

Consultar periódicamente el estado:

```javascript
setInterval(async () => {
  const cves = await getCVEs();
  updateDashboard(cves);
}, 60000); // Cada minuto
```

---

¡Estos ejemplos cubren los casos de uso más comunes! 🚀

