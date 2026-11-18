from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Crear base de datos en memoria con datos de prueba
def init_db():
    conn = sqlite3.connect('usuarios.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)')
    c.execute("INSERT INTO users VALUES (1, 'admin', 'SuperSecreto123', 'administrador')")
    c.execute("INSERT INTO users VALUES (2, 'juan', 'clave2026', 'usuario')")
    conn.commit()
    conn.close()

HTML_HOME = """
<!DOCTYPE html>
<html>
<head><title>Portal Vulnerable - Práctica Seguridad</title></head>
<body>
    <h1>Sistema de Consulta de Empleados</h1>
    
    <!-- VULNERABILIDAD 1: SQL Injection (A03:2021 - Injection) -->
    <h3>1. Buscar Usuario (SQLi)</h3>
    <form action="/buscar" method="GET">
        ID Usuario: <input type="text" name="id" value="1">
        <input type="submit" value="Buscar">
    </form>

    <!-- VULNERABILIDAD 2: Cross-Site Scripting Reflejado (A03:2021 - Injection) -->
    <h3>2. Mensaje de Bienvenida (XSS Reflejado)</h3>
    <form action="/saludo" method="GET">
        Tu nombre: <input type="text" name="nombre" value="Invitado">
        <input type="submit" value="Saludar">
    </form>

    <!-- VULNERABILIDAD 3: Control de Acceso Roto / IDOR (A01:2021 - Broken Access Control) -->
    <h3>3. Panel de Administración</h3>
    <a href="/admin?role=user">Entrar al panel</a>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_HOME)

# 1. SQL INJECTION (Concatenación directa sin parametrizar)
@app.route('/buscar')
def buscar():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('usuarios.db')
    c = conn.cursor()
    try:
        query = f"SELECT username, role FROM users WHERE id = {user_id}"
        c.execute(query)
        resultados = c.fetchall()
        return f"<h2>Resultados:</h2><p>{resultados}</p><a href='/'>Volver</a>"
    except Exception as e:
        return f"<h2>Error SQL:</h2><p>{str(e)}</p>"

# 2. XSS REFLEJADO (Renderiza HTML sin escapar)
@app.route('/saludo')
def saludo():
    nombre = request.args.get('nombre', '')
    return f"<h2>Hola, {nombre}!</h2><a href='/'>Volver</a>"

# 3. BROKEN ACCESS CONTROL (Confía en parámetro de URL sin validar sesión)
@app.route('/admin')
def admin():
    role = request.args.get('role', 'user')
    if role == 'admin':
        return "<h2>PANEL DE ADMINISTRADOR: Acceso concedido a datos confidenciales.</h2>"
    return "<h2>Acceso Denegado. Necesitas role=admin</h2>", 403

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)