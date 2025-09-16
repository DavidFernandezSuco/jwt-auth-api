package com.davidfernandez.jwt_auth_api.security;

import com.davidfernandez.jwt_auth_api.service.AuthService;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuración principal de Spring Security con autenticación JWT
 *
 * Esta clase configura:
 * - Qué endpoints están protegidos y cuáles son públicos
 * - Cómo se autentica a los usuarios (JWT vs formulario)
 * - Los beans necesarios para el sistema de autenticación
 * - El filtro JWT personalizado
 */
@Configuration
@EnableWebSecurity  // Habilita Spring Security
@EnableMethodSecurity  // Permite usar @PreAuthorize en métodos
public class SecurityConfig {

    private final AuthService authService;
    private final JwtAuthFilter jwtAuthFilter;

    @Autowired
    public SecurityConfig(AuthService authService, JwtAuthFilter jwtAuthFilter) {
        this.authService = authService;
        this.jwtAuthFilter = jwtAuthFilter;
    }

    /**
     * Configuración principal de seguridad
     * Define qué endpoints están protegidos y cómo
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Deshabilitar CSRF (no lo necesitamos para APIs REST con JWT)
                .csrf(AbstractHttpConfigurer::disable)

                // Configurar autorización de endpoints
                .authorizeHttpRequests(auth -> auth
                        // Endpoints públicos (no requieren autenticación)
                        .requestMatchers("/auth/**").permitAll()  // Login, registro
                        .requestMatchers("/h2-console/**").permitAll()  // Base de datos H2
                        .requestMatchers("/actuator/**").permitAll()  // Spring Actuator (si lo usas)

                        // Endpoints que requieren rol ADMIN
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // Endpoints que requieren rol USER o ADMIN
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")

                        // Cualquier otra petición requiere autenticación
                        .anyRequest().authenticated()
                )

                // Configurar manejo de sesiones (sin estado para JWT)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configurar proveedor de autenticación
                .authenticationProvider(authenticationProvider())

                // Añadir nuestro filtro JWT antes del filtro de username/password
                .addFilterBefore((Filter) jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                // Configurar headers para H2 Console
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())
                );

        return http.build();
    }

    /**
     * Bean para encriptar passwords
     * BCrypt es muy seguro y recomendado por Spring Security
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Proveedor de autenticación personalizado
     * Conecta nuestro AuthService con el PasswordEncoder
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(authService);  // Nuestro AuthService
        authProvider.setPasswordEncoder(passwordEncoder());  // BCrypt
        return authProvider;
    }

    /**
     * AuthenticationManager bean requerido para el proceso de login
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}