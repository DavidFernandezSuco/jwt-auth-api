package com.davidfernandez.jwt_auth_api.dto;

import java.time.LocalDateTime;

/**
 * DTO para mostrar información de usuarios sin datos sensibles
 * Se usa en endpoints que devuelven información de usuarios (GET /users, GET /profile, etc.)
 *
 * IMPORTANTE: NO incluye la password por seguridad
 *
 * Ejemplo de JSON que enviamos:
 * {
 *   "id": 1,
 *   "username": "juan123",
 *   "email": "juan@example.com",
 *   "role": "USER",
 *   "createdAt": "2024-09-16T21:30:00",
 *   "enabled": true
 * }
 */
public class UserDto {

    private Long id;
    private String username;
    private String email;
    private String role;  // Como String para simplificar el JSON
    private LocalDateTime createdAt;
    private boolean enabled;

    // Constructor vacío (necesario para Jackson)
    public UserDto() {}

    // Constructor completo para crear desde entidad User
    public UserDto(Long id, String username, String email, String role,
                   LocalDateTime createdAt, boolean enabled) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.createdAt = createdAt;
        this.enabled = enabled;
    }

    // Método estático helper para convertir de User entity a UserDto fácilmente
    // Uso: UserDto.fromUser(userEntity)
    public static UserDto fromUser(com.davidfernandez.jwt_auth_api.entity.User user) {
        return new UserDto(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(), // Convierte enum a String
                user.getCreatedAt(),
                user.isEnabled()
        );
    }

    // Getters y Setters (necesarios para JSON serialization)

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    // toString para debugging
    @Override
    public String toString() {
        return "UserDto{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", role='" + role + '\'' +
                ", createdAt=" + createdAt +
                ", enabled=" + enabled +
                '}';
    }
}