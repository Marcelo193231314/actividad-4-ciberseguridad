from flask import Flask, request, jsonify
import jwt
import datetime
import re
import time

app = Flask(__name__)
SECRET_KEY = "ClaveSuperSecretaDeFirmaJWT_2026"

# Registro en memoria para Rate Limiting (100 solicitudes por minuto)
request_logs = {}
RATE_LIMIT = 100
TIME_WINDOW = 60  # segundos

@app.before_request
def check_rate_limit():
    client_ip = request.remote_addr
    now = time.time()
    # Limpiar registros viejos mayores a 60 segundos
    request_logs[client_ip] = [t for t in request_logs.get(client_ip, []) if now - t < TIME_WINDOW]
    
    if len(request_logs[client_ip]) >= RATE_LIMIT:
        return jsonify({
            "error": "Too Many Requests",
            "message": "Has excedido el límite de 100 solicitudes por minuto."
        }), 429
    
    request_logs[client_ip].append(now)

# 1. ENDPOINT OAUTH 2.0 / GENERACIÓN DE JWT
@app.route('/oauth/token', methods=['POST'])
def get_token():
    data = request.get_json() or {}
    if data.get("grant_type") == "client_credentials" and data.get("client_id") == "cliente_app" and data.get("client_secret") == "secreto_123":
        payload = {
            "sub": "cliente_app",
            "role": "admin",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 1800
        }), 200
    return jsonify({"error": "invalid_client"}), 401

# 2. ENDPOINT PROTEGIDO CON JWT Y VALIDACIÓN ANTI-INYECCIÓN SQL
@app.route('/api/v1/usuarios', methods=['POST'])
def consultar_usuario():
    # Validar cabecera Authorization: Bearer <token>
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Token JWT faltante o mal formado"}), 401
    
    token = auth_header.split(" ")[1]
    try:
        # Rechaza explícitamente alg: none exigiendo HS256
        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token JWT inválido o expirado"}), 403

    # Validación estricta de entrada (solo números enteros permitidos)
    data = request.get_json() or {}
    user_id = str(data.get("user_id", ""))
    
    if not re.match(r"^\d+$", user_id):
        return jsonify({
            "error": "Bad Request - Posible Inyección SQL detectada",
            "detalle": "El campo user_id solo acepta valores numéricos enteros."
        }), 400

    return jsonify({
        "status": "success",
        "usuario": {"id": int(user_id), "nombre": "Alvaro Silva", "rol": "Ingeniero"}
    }), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)