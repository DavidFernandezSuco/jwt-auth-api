package com.davidfernandez.jwt_auth_api.controller;

import com.davidfernandez.jwt_auth_api.dto.LoginRequest;
import com.davidfernandez.jwt_auth_api.dto.LoginResponse;
import com.davidfernandez.jwt_auth_api.dto.UserDto;
import com.davidfernandez.jwt_auth_api.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * Controller para manejar la autenticación
 *
 * Endpoints disponibles:
 * - POST /auth/login - Login con credenciales
 * - GET /auth/me - Obtener información del usuario autenticado
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint para hacer login
     *
     * @param loginRequest credenciales del usuario (username, password)
     * @return LoginResponse con token JWT y datos del usuario
     *
     * Ejemplo de uso:
     * POST /auth/login
     * {
     *   "username": "admin",
     *   "password": "admin123"
     * }
     *
     * Respuesta:
     * {
     *   "token": "eyJhbGciOiJIUzI1NiJ9...",
     *   "type": "Bearer",
     *   "username": "admin",
     *   "email": "admin@example.com",
     *   "role": "ADMIN"
     * }
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            LoginResponse response = authService.login(loginRequest);
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            return ResponseEntity.badRequest()
                    .body("Error: Credenciales inválidas");
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Error: " + e.getMessage());
        }
    }

    /**
     * Endpoint para obtener información del usuario autenticado
     * Requiere token JWT válido en el header Authorization
     *
     * @return UserDto con información del usuario actual
     *
     * Ejemplo de uso:
     * GET /auth/me
     * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
     *
     * Respuesta:
     * {
     *   "id": 1,
     *   "username": "admin",
     *   "email": "admin@example.com",
     *   "role": "ADMIN",
     *   "createdAt": "2024-09-16T21:30:00",
     *   "enabled": true
     * }
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        try {
            // Obtener el usuario autenticado del contexto de Spring Security
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();

            UserDto user = authService.getCurrentUser(username);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body("Error obteniendo usuario: " + e.getMessage());
        }
    }
}