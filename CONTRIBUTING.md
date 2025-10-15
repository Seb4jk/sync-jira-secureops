# Guía de Contribución

## 🤝 Cómo Contribuir

¡Gracias por tu interés en contribuir a este proyecto! Sigue estas pautas para asegurar un proceso fluido.

## 📋 Antes de Empezar

1. **Fork** el repositorio
2. **Clona** tu fork localmente
3. **Crea una rama** para tu feature o bugfix
4. **Haz tus cambios** siguiendo las guías de estilo
5. **Ejecuta las pruebas** (cuando estén disponibles)
6. **Crea un Pull Request**

## 🌿 Flujo de Git

### Crear una Rama

```bash
# Para una nueva feature
git checkout -b feature/nombre-descriptivo

# Para un bugfix
git checkout -b fix/descripcion-del-bug

# Para documentación
git checkout -b docs/mejora-documentacion
```

### Commits

Usa mensajes de commit descriptivos siguiendo el formato:

```
tipo(alcance): descripción breve

Descripción más detallada si es necesario.

Fixes #123
```

**Tipos de commit:**
- `feat`: Nueva funcionalidad
- `fix`: Corrección de bugs
- `docs`: Cambios en documentación
- `style`: Formato, puntos y comas faltantes, etc.
- `refactor`: Refactorización de código
- `test`: Agregar tests
- `chore`: Tareas de mantenimiento

**Ejemplos:**
```
feat(auth): agregar autenticación con OAuth2

fix(wazuh): corregir timeout en llamadas a API

docs(readme): actualizar instrucciones de instalación

refactor(services): simplificar lógica de sincronización
```

## 📝 Guías de Estilo

### TypeScript

- Usa **tipos explícitos** siempre que sea posible
- Evita `any`, usa `unknown` si no conoces el tipo
- Usa **interfaces** para objetos y **types** para unions/intersections
- Nombres de variables y funciones en **camelCase**
- Nombres de clases e interfaces en **PascalCase**
- Nombres de constantes en **UPPER_SNAKE_CASE** si son globales
- Usa **arrow functions** para callbacks
- Documenta funciones públicas con JSDoc

**Ejemplo:**
```typescript
/**
 * Obtiene los detalles de un CVE específico
 * @param cveId - Identificador del CVE
 * @returns Promise con los datos del CVE o null
 */
async function getCVEDetails(cveId: string): Promise<CVE | null> {
  // implementación
}
```

### Estructura de Archivos

- **Un archivo, una responsabilidad**
- Agrupa exports relacionados
- Mantén archivos menores a 300 líneas cuando sea posible
- Usa barrel exports (`index.ts`) para simplificar imports

### Manejo de Errores

- Usa la clase `AppError` para errores de aplicación
- Proporciona mensajes de error claros y descriptivos
- Log errores con el nivel apropiado
- Nunca expongas información sensible en errores

**Ejemplo:**
```typescript
if (!user) {
  throw new AppError('Usuario no encontrado', 404);
}
```

### Logging

Usa los niveles apropiados:
- **error**: Errores críticos
- **warn**: Advertencias, errores recuperables
- **info**: Información importante de flujo
- **debug**: Información de debugging (solo desarrollo)

```typescript
logger.info('Iniciando sincronización', { cveCount: cves.length });
logger.error('Error al conectar con Wazuh', { error: err.message });
```

## 🧪 Testing (Futuro)

Cuando se implementen tests:

```bash
# Ejecutar tests
npm test

# Ejecutar tests con coverage
npm run test:coverage

# Ejecutar tests en modo watch
npm run test:watch
```

## 📦 Agregar Dependencias

Antes de agregar una nueva dependencia:

1. **Evalúa si es realmente necesaria**
2. **Verifica la licencia** (debe ser compatible)
3. **Revisa el mantenimiento** (última actualización, issues abiertas)
4. **Considera el tamaño** del bundle

```bash
# Instalar dependencia de producción
npm install package-name

# Instalar dependencia de desarrollo
npm install --save-dev package-name
```

Actualiza el README si la dependencia es importante.

## 🔍 Revisión de Código

Al hacer un Pull Request, asegúrate de:

- [ ] El código sigue las guías de estilo
- [ ] No hay código comentado innecesario
- [ ] Las variables tienen nombres descriptivos
- [ ] No hay secrets o credenciales hardcodeadas
- [ ] Los errores se manejan apropiadamente
- [ ] El código está documentado
- [ ] No introduces linter warnings
- [ ] Los cambios están probados manualmente

## 🐛 Reportar Bugs

Usa el template de issue e incluye:

1. **Descripción clara** del bug
2. **Pasos para reproducir**
3. **Comportamiento esperado** vs **comportamiento actual**
4. **Entorno** (OS, Node version, etc.)
5. **Logs** relevantes
6. **Screenshots** si aplica

## 💡 Sugerir Features

Para sugerir una nueva funcionalidad:

1. **Verifica** que no exista un issue similar
2. **Describe** el problema que resuelve
3. **Propón** una solución o implementación
4. **Considera** el impacto en el proyecto existente

## 📄 Licencia

Al contribuir, aceptas que tus contribuciones serán licenciadas bajo la misma licencia que el proyecto (ISC).

## 🙏 Reconocimientos

Todos los contribuidores serán reconocidos en el README del proyecto.

---

¡Gracias por contribuir! 🎉

