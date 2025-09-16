package com.davidfernandez.jwt_auth_api.security;

import com.davidfernandez.jwt_auth_api.service.AuthService;
import com.davidfernandez.jwt_auth_api.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro que se ejecuta en CADA petición HTTP para validar el token JWT
 *
 * Flujo del filtro:
 * 1. Extrae el token JWT del header "Authorization: Bearer <token>"
 * 2. Si hay token, valida que sea correcto y no haya expirado
 * 3. Si es válido, carga el usuario y lo autentica en Spring Security
 * 4. Continúa con la petición (o rechaza si el token es inválido)
 *
 * Este filtro se ejecuta ANTES que otros filtros de Spring Security
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AuthService authService;

    @Autowired
    public JwtAuthFilter(JwtService jwtService, AuthService authService) {
        this.jwtService = jwtService;
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Extraer el header Authorization
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // 2. Verificar que el header existe y empieza con "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // No hay token JWT - continuar con el siguiente filtro
            // (Spring Security manejará la autenticación de otra forma o rechazará)
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Extraer el token (quitar "Bearer " del inicio)
        jwt = authHeader.substring(7);  // "Bearer " tiene 7 caracteres

        try {
            // 4. Extraer el username del token
            username = jwtService.extractUsername(jwt);

            // 5. Si tenemos username Y el usuario no está ya autenticado en esta petición
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 6. Cargar los detalles del usuario de la base de datos
                UserDetails userDetails = this.authService.loadUserByUsername(username);

                // 7. Validar que el token sea correcto para este usuario
                if (jwtService.isTokenValid(jwt, userDetails)) {

                    // 8. Crear token de autenticación para Spring Security
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,  // No necesitamos la password aquí
                            userDetails.getAuthorities()  // Roles del usuario
                    );

                    // 9. Añadir detalles de la petición (IP, etc.)
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // 10. Establecer la autenticación en el contexto de Spring Security
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // Token inválido o ha ocurrido un error - no autenticar
            // El log puede ser útil para debugging
            logger.error("Error validating JWT token: " + e.getMessage());
        }

        // 11. Continuar con el siguiente filtro (siempre, autenticado o no)
        filterChain.doFilter(request, response);
    }
}