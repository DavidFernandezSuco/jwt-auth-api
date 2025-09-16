package com.davidfernandez.jwt_auth_api.dto;

/**
 * DTO para enviar la respuesta cuando el login es exitoso
 * Se devuelve como JSON al frontend después de autenticar correctamente
 *
 * Ejemplo de JSON que enviamos:
 * {
 *   "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIi...",
 *   "type": "Bearer",
 *   "username": "juan123",
 *   "email": "juan@example.com",
 *   "role": "USER"
 * }
 */
public class LoginResponse {

    // El token JWT que el frontend debe incluir en futuras peticiones
    private String token;

    // Tipo de token (siempre será "Bearer" para JWT)
    private String type = "Bearer";

    // Información básica del usuario autenticado
    private String username;
    private String email;
    private String role;

    // Constructor vacío (necesario para Jackson)
    public LoginResponse() {}

    // Constructor principal para crear respuestas fácilmente
    public LoginResponse(String token, String username, String email, String role) {
        this.token = token;
        this.username = username;
        this.email = email;
        this.role = role;
    }

    // Getters y Setters (necesarios para JSON serialization)

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    // toString para debugging (muestra token parcial por seguridad)
    @Override
    public String toString() {
        return "LoginResponse{" +
                "token='" + (token != null ? token.substring(0, Math.min(token.length(), 20)) + "..." : "null") + '\'' +
                ", type='" + type + '\'' +
                ", username='" + username + '\'' +
                ", role='" + role + '\'' +
                '}';
    }
}