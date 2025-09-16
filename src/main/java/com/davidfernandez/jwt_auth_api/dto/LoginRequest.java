package com.davidfernandez.jwt_auth_api.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO (Data Transfer Object) para recibir las credenciales de login
 * Se usa cuando el frontend envía POST /auth/login
 *
 * Ejemplo de JSON que recibimos:
 * {
 *   "username": "juan123",
 *   "password": "mipassword"
 * }
 */
public class LoginRequest {

    // Campo username: debe estar presente y no estar vacío
    @NotBlank(message = "El username es obligatorio")
    private String username;

    // Campo password: debe estar presente y no estar vacío
    @NotBlank(message = "La password es obligatoria")
    private String password;

    // Constructor vacío (necesario para que Jackson pueda crear el objeto desde JSON)
    public LoginRequest() {}

    // Constructor completo (útil para crear objetos en tests)
    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters y Setters (necesarios para que Jackson lea/escriba el JSON)

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    // toString para debugging (NO incluye password por seguridad)
    @Override
    public String toString() {
        return "LoginRequest{" +
                "username='" + username + '\'' +
                '}';
    }
}