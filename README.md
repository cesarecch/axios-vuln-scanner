# axios-vuln-scanner

Herramienta de consola portable para detectar proyectos afectados por el **ataque supply chain a Axios** del 31 de marzo de 2026.

## El ataque

El 31 de marzo de 2026, la cuenta del mantenedor principal de `axios` fue comprometida y se publicaron dos versiones maliciosas en npm:

| Versión maliciosa | Estado |
|---|---|
| `axios@1.14.1` | ⛔ COMPROMETIDA — NO USAR |
| `axios@0.30.4` | ⛔ COMPROMETIDA — NO USAR |

Las versiones maliciosas inyectaron una dependencia fantasma llamada `plain-crypto-js` que desplegaba un **Remote Access Trojan (RAT)** multiplataforma (Windows, macOS, Linux). El malware se auto-eliminaba después de la instalación para no dejar rastros visibles en `node_modules`.

**Versiones seguras:**
- `axios@1.14.0` (1.x)
- `axios@0.30.3` (0.x)

## Requisitos

Solo necesitas **Node.js** (cualquier versión ≥ 12). No requiere instalar dependencias adicionales.

## Uso

```bash
node axios-vuln-scanner.js <ruta> [opciones]
```

### Ejemplos

```bash
# Escanear el directorio actual
node axios-vuln-scanner.js .

# Escanear una carpeta de proyectos
node axios-vuln-scanner.js /home/usuario/proyectos

# Windows
node axios-vuln-scanner.js C:\Users\usuario\source

# Limitar profundidad de búsqueda a 3 niveles (por defecto es infinita)
node axios-vuln-scanner.js /proyectos --depth 3

# Sin colores (para CI/CD o pipes)
node axios-vuln-scanner.js . --no-color
```

## Qué analiza

Para cada subdirectorio que contenga un `package.json`, el scanner revisa:

| Archivo | Qué busca |
|---|---|
| `package.json` | Versiones maliciosas en dependencies/devDependencies |
| `package-lock.json` | Versiones resueltas maliciosas (npm) |
| `yarn.lock` | Versiones resueltas maliciosas (Yarn) |
| `pnpm-lock.yaml` | Versiones resueltas maliciosas (pnpm) |
| `node_modules/axios/package.json` | Versión **instalada** maliciosa |
| `node_modules/plain-crypto-js/` | Presencia de la dependencia fantasma |

Además, verifica en el sistema de archivos local la presencia de **artefactos del RAT**:

| Sistema | Artefacto |
|---|---|
| Windows | `%PROGRAMDATA%\wt.exe` |
| macOS | `/Library/Caches/com.apple.act.mond` |
| Linux | `/tmp/ld.py` |

## Indicadores de Compromiso (IOCs)

| Tipo | Valor |
|---|---|
| Dominio C2 | `sfrclak.com` |
| IP C2 | `142.11.206.73:8000` |
| Endpoint C2 | `/6202033` |
| Hash `axios@1.14.1` | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| Hash `axios@0.30.4` | `2553649f232204966871cea80a5d0d6adc700ca` |
| Hash `plain-crypto-js@4.2.1` | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

## Remediación

### Si el scanner encuentra versiones afectadas en lockfiles

```bash
# Para proyectos 1.x
npm install axios@1.14.0

# Para proyectos 0.x
npm install axios@0.30.3
```

### Si encuentra plain-crypto-js instalado

```bash
rm -rf node_modules/plain-crypto-js
npm ci --ignore-scripts
```

### Si encuentra artefactos del RAT en el sistema

> ⚠️ **Asume compromiso total del sistema**

1. **No intentes limpiar en el lugar** — reconstruye la máquina desde un estado limpio conocido
2. **Rota TODAS las credenciales** del sistema afectado:
   - Tokens npm
   - Claves SSH
   - Credenciales AWS/GCP/Azure
   - Secretos de CI/CD
   - Passwords de bases de datos
   - Archivos `.env`
3. **Audita los pipelines de CI/CD** que ejecutaron `npm install` entre las 00:21 UTC y las 03:15 UTC del 31 de marzo de 2026
4. Bloquea `sfrclak.com` y `142.11.206.73` en firewall/DNS

## Prevención futura

- Usar `npm ci --ignore-scripts` en CI/CD para bloquear postinstall hooks
- Siempre usar lockfiles en entornos automatizados
- Considerar herramientas como [Socket Security](https://socket.dev) o [Aikido](https://www.aikido.dev)
- Enforcar versiones pinned (sin `^` o `~`) en proyectos críticos

## Referencias

- [Socket Security: Supply Chain Attack on Axios](https://socket.dev/blog/axios-npm-package-compromised)
- [IronPlate: Full Breakdown of the 2026 Supply Chain Attack](https://ironplate.ai/blog/axios-npm-supply-chain-attack)
- [StepSecurity: axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Aikido: axios npm Compromised](https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat)
