package com.davidfernandez.jwt_auth_api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller para probar la protección de endpoints con diferentes roles
 *
 * Endpoints disponibles:
 * - GET /admin/test - Solo accesible por usuarios con rol ADMIN
 * - GET /user/test - Accesible por usuarios con rol USER o ADMIN
 * - GET /public/test - Accesible sin autenticación
 */
@RestController
public class TestController {

    /**
     * Endpoint público - no requiere autenticación
     *
     * GET /public/test
     * No requiere token JWT
     */
    @GetMapping("/public/test")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Este es un endpoint público");
        response.put("timestamp", LocalDateTime.now());
        response.put("access", "public");
        response.put("description", "Cualquiera puede acceder sin autenticación");

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint para usuarios normales
     * Requiere rol USER o ADMIN
     *
     * GET /user/test
     * Authorization: Bearer <token_jwt>
     */
    @GetMapping("/user/test")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> userEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Endpoint accesible para usuarios autenticados");
        response.put("timestamp", LocalDateTime.now());
        response.put("access", "user");
        response.put("username", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("description", "Requiere rol USER o ADMIN");

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint solo para administradores
     * Requiere rol ADMIN exclusivamente
     *
     * GET /admin/test
     * Authorization: Bearer <token_jwt>
     */
    @GetMapping("/admin/test")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> adminEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Endpoint exclusivo para administradores");
        response.put("timestamp", LocalDateTime.now());
        response.put("access", "admin");
        response.put("username", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("description", "Solo usuarios con rol ADMIN pueden acceder");
        response.put("warning", "Información sensible de administración");

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint para obtener información detallada del usuario autenticado
     * Útil para debugging y verificar qué datos tiene Spring Security
     *
     * GET /debug/auth
     * Authorization: Bearer <token_jwt>
     */
    @GetMapping("/debug/auth")
    public ResponseEntity<Map<String, Object>> debugAuth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("authenticated", auth.isAuthenticated());
        response.put("principal", auth.getPrincipal());
        response.put("authorities", auth.getAuthorities());
        response.put("name", auth.getName());
        response.put("details", auth.getDetails());
        response.put("timestamp", LocalDateTime.now());

        return ResponseEntity.ok(response);
    }
}