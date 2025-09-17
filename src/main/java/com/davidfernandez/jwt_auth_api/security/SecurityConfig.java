package com.davidfernandez.jwt_auth_api.security;

import com.davidfernandez.jwt_auth_api.service.AuthService;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Main Spring Security configuration with JWT authentication
 *
 * This class configures:
 * - Which endpoints are protected and which are public
 * - How users are authenticated (JWT vs form)
 * - The beans needed for the authentication system
 * - The custom JWT filter
 */
@Configuration
@EnableWebSecurity  // Enable Spring Security
@EnableMethodSecurity  // Allow using @PreAuthorize on methods
public class SecurityConfig {

    private final AuthService authService;
    private final JwtAuthFilter jwtAuthFilter;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(AuthService authService,
                          JwtAuthFilter jwtAuthFilter,
                          PasswordEncoder passwordEncoder) {
        this.authService = authService;
        this.jwtAuthFilter = jwtAuthFilter;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Main security configuration
     * Defines which endpoints are protected and how
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF (not needed for REST APIs with JWT)
                .csrf(AbstractHttpConfigurer::disable)

                // Configure endpoint authorization
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints (no authentication required)
                        .requestMatchers("/auth/**").permitAll()  // Login, register
                        .requestMatchers("/h2-console/**").permitAll()  // H2 database
                        .requestMatchers("/actuator/**").permitAll()  // Spring Actuator (if used)
                        .requestMatchers("/public/**").permitAll()  // Public test endpoints

                        // Endpoints that require ADMIN role
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        // Endpoints that require USER or ADMIN role
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")

                        // Any other request requires authentication
                        .anyRequest().authenticated()
                )

                // Configure session management (stateless for JWT)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configure authentication provider
                .authenticationProvider(authenticationProvider())

                // Add our JWT filter before username/password filter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                // Configure headers for H2 Console
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())
                );

        return http.build();
    }

    /**
     * Custom authentication provider
     * Connects our AuthService with the PasswordEncoder
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(authService);  // Our AuthService
        authProvider.setPasswordEncoder(passwordEncoder);  // BCrypt from BeanConfig
        return authProvider;
    }

    /**
     * AuthenticationManager bean required for login process
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}