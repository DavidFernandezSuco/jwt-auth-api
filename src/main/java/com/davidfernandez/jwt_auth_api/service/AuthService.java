package com.davidfernandez.jwt_auth_api.service;

import com.davidfernandez.jwt_auth_api.dto.LoginRequest;
import com.davidfernandez.jwt_auth_api.dto.LoginResponse;
import com.davidfernandez.jwt_auth_api.dto.UserDto;
import com.davidfernandez.jwt_auth_api.entity.User;
import com.davidfernandez.jwt_auth_api.entity.Role;
import com.davidfernandez.jwt_auth_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Servicio principal de autenticación
 *
 * Responsabilidades:
 * - Manejar el proceso de login (validar credenciales + generar JWT)
 * - Implementar UserDetailsService para Spring Security
 * - Crear usuarios iniciales (admin, user de prueba)
 * - Obtener información del usuario autenticado
 */
@Service
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    // Constructor - Spring inyecta automáticamente las dependencias
    @Autowired
    public AuthService(UserRepository userRepository,
                       JwtService jwtService,
                       PasswordEncoder passwordEncoder,
                       AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Procesa el login del usuario
     *
     * 1. Valida las credenciales con Spring Security
     * 2. Si es válido, genera un token JWT
     * 3. Devuelve la respuesta con token + info del usuario
     *
     * @param request credenciales del usuario (username, password)
     * @return LoginResponse con token JWT y datos del usuario
     * @throws BadCredentialsException si las credenciales son incorrectas
     */
    public LoginResponse login(LoginRequest request) {
        try {
            // 1. Autenticar con Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            // 2. Si llegamos aquí, las credenciales son válidas
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userRepository.findByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // 3. Generar token JWT
            String token = jwtService.generateToken(userDetails);

            // 4. Crear y devolver respuesta
            return new LoginResponse(
                    token,
                    user.getUsername(),
                    user.getEmail(),
                    user.getRole().name()
            );

        } catch (Exception e) {
            throw new BadCredentialsException("Credenciales inválidas");
        }
    }

    /**
     * Obtiene información del usuario autenticado actual
     *
     * @param username nombre del usuario (extraído del JWT)
     * @return UserDto con información del usuario
     */
    public UserDto getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        return UserDto.fromUser(user);
    }

    /**
     * Implementación de UserDetailsService para Spring Security
     * Este método se llama automáticamente cuando Spring Security necesita cargar un usuario
     *
     * @param username nombre del usuario a cargar
     * @return UserDetails del usuario (nuestra entidad User implementa esta interfaz)
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
    }

    /**
     * Método helper para crear usuarios de prueba
     * Se puede llamar desde un @PostConstruct o desde un DataInitializer
     */
    public User createUser(String username, String email, String password, Role role) {
        // Verificar que no existe ya el usuario
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("El username ya existe: " + username);
        }
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("El email ya existe: " + email);
        }

        // Crear nuevo usuario con password encriptada
        User user = new User(username, email, passwordEncoder.encode(password), role);
        return userRepository.save(user);
    }
}