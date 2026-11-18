# Actividad 4: Seguridad en Aplicaciones Web, APIs y Perímetro de Red

**Autor:** Alvaro Marcelo Silva Amaro (AL07023903)  
**Institución:** Universidad Tecmilenio  

Este repositorio contiene el código fuente, las colecciones de pruebas, los respaldos de configuración del firewall y las reglas de detección de intrusos desarrolladas para la Actividad 4 de Ciberseguridad.

---

## Estructura y Descripción de Archivos

### 1. Análisis de Vulnerabilidades Web
* **`app_vulnerable.py`**: Aplicación web desarrollada en Python con Flask desplegada de forma controlada en entorno local (`http://127.0.0.1:5000`)[cite: 15]. Expone rutas sin sanitización de entradas ni controles de acceso para realizar auditorías automatizadas con **OWASP ZAP** e identificar vulnerabilidades del OWASP Top 10 (Inyección SQL, Cross-Site Scripting Reflejado y Ruta Transversal)[cite: 15, 16, 17].
* **`usuarios.db`**: Base de datos ligera en **SQLite** utilizada por las aplicaciones Flask para almacenar registros de prueba y validar tanto la explotación por concatenación de consultas como la mitigación mediante consultas parametrizadas (*Prepared Statements*)[cite: 16, 25].

### 2. Protección y Hardening de APIs
* **`api_segura.py`**: Implementación endurecida de la API en Python/Flask (`http://127.0.0.1:5001`)[cite: 17]. Incorpora autenticación y autorización mediante **OAuth 2.0 y tokens JWT firmados criptográficamente (HS256)**[cite: 17], validación estricta de parámetros mediante expresiones regulares (`^\d+$`) para bloquear inyecciones SQL[cite: 18, 25], y políticas de **Rate Limiting** (máximo 100 solicitudes por minuto por IP, devolviendo código `HTTP 429 Too Many Requests` al superar el umbral)[cite: 19].
* **`Coleccion_API_Segura.json`**: Colección exportada de **Postman** con las peticiones configuradas para validar la obtención de tokens OAuth 2.0, el acceso autorizado con `Bearer Token` (`200 OK`)[cite: 17], el rechazo de cargas maliciosas SQLi (`400 Bad Request`)[cite: 18] y las pruebas de carga con el *Collection Runner*[cite: 19].

### 3. Seguridad Perimetral y Detección de Intrusos (pfSense + Snort)
* **`config-pfSense.xml.xml`**: Respaldo completo de configuración del firewall perimetral **pfSense**[cite: 27]. Incluye las reglas de filtrado de paquetes en la interfaz `LAN` bajo el principio de mínimo privilegio (aislamiento de la red interna `192.168.20.0/24`, bloqueo de acceso administrativo SSH y tráfico autorizado HTTPS hacia la DMZ `172.16.10.0/24`)[cite: 20, 21], así como la configuración de **pfBlockerNG (DNSBL)** con el grupo `Phishing_Block` en modo `Unbound` para bloquear dominios maliciosos[cite: 22].
* **`custom.rules`** *(Regla personalizada de Snort integrada)*: Firma local configurada en el motor IDS/IPS **Snort** (`SID: 1000001`) para inspeccionar paquetes TCP con bandera `SYN` y alertar ante escaneos de reconocimiento realizados con **Nmap**[cite: 23]:
  ```snort
  alert tcp any any -> $HOME_NET any (msg:"Deteccion de Escaneo de Puertos Nmap"; flags:S; threshold: type both, track by_src, count 10, seconds 5; sid:1000001; rev:1;)
