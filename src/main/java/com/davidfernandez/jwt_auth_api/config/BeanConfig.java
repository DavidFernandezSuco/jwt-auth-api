package com.davidfernandez.jwt_auth_api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration for basic beans that don't have circular dependencies
 *
 * This class loads before SecurityConfig and AuthService,
 * providing fundamental beans like PasswordEncoder
 */
@Configuration
public class BeanConfig {

    /**
     * Bean for password encryption
     * BCrypt is very secure and recommended by Spring Security
     *
     * By being in a separate class, it avoids circular dependencies
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}