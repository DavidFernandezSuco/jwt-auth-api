package com.davidfernandez.jwt_auth_api.config;

import com.davidfernandez.jwt_auth_api.entity.Role;
import com.davidfernandez.jwt_auth_api.entity.User;
import com.davidfernandez.jwt_auth_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Inicializador de datos que se ejecuta al arrancar la aplicación
 *
 * Crea usuarios de prueba para poder testear la API inmediatamente:
 * - admin/admin123 (rol ADMIN)
 * - user/user123 (rol USER)
 *
 * Solo se ejecuta si los usuarios no existen ya en la base de datos
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Método que se ejecuta automáticamente después de que Spring Boot arranque
     */
    @Override
    public void run(String... args) throws Exception {
        createDefaultUsers();
    }

    /**
     * Crea usuarios por defecto para poder testear la aplicación
     */
    private void createDefaultUsers() {
        try {
            // Crear usuario ADMIN
            createUserIfNotExists(
                    "admin",
                    "admin@example.com",
                    "admin123",
                    Role.ADMIN,
                    "Administrador del sistema"
            );

            // Crear usuario normal
            createUserIfNotExists(
                    "user",
                    "user@example.com",
                    "user123",
                    Role.USER,
                    "Usuario normal de prueba"
            );

            // Crear usuario adicional para más tests
            createUserIfNotExists(
                    "juan",
                    "juan@example.com",
                    "juan123",
                    Role.USER,
                    "Usuario adicional para pruebas"
            );

            System.out.println("\n" + "=".repeat(60));
            System.out.println("🚀 USUARIOS DE PRUEBA CREADOS EXITOSAMENTE");
            System.out.println("=".repeat(60));
            System.out.println("📋 Usuarios disponibles para login:");
            System.out.println("   👑 ADMIN: username=admin, password=admin123");
            System.out.println("   👤 USER:  username=user,  password=user123");
            System.out.println("   👤 USER:  username=juan,  password=juan123");
            System.out.println("\n🔗 Endpoints para probar:");
            System.out.println("   POST /auth/login    - Obtener token JWT");
            System.out.println("   GET  /auth/me       - Info usuario autenticado");
            System.out.println("   GET  /public/test   - Endpoint público");
            System.out.println("   GET  /user/test     - Requiere USER o ADMIN");
            System.out.println("   GET  /admin/test    - Solo ADMIN");
            System.out.println("   GET  /debug/auth    - Debug autenticación");
            System.out.println("\n💡 Para usar JWT:");
            System.out.println("   1. POST /auth/login con credenciales");
            System.out.println("   2. Copiar el 'token' de la respuesta");
            System.out.println("   3. Añadir header: Authorization: Bearer <token>");
            System.out.println("=".repeat(60) + "\n");

        } catch (Exception e) {
            System.err.println("❌ Error creando usuarios de prueba: " + e.getMessage());
        }
    }

    /**
     * Crea un usuario solo si no existe ya
     */
    private void createUserIfNotExists(String username, String email, String password, Role role, String description) {
        try {
            // Verificar que no existe ya el usuario
            if (userRepository.existsByUsername(username)) {
                System.out.println("ℹ️  Usuario ya existe: " + username + " (" + role + ")");
                return;
            }
            if (userRepository.existsByEmail(email)) {
                System.out.println("ℹ️  Email ya existe: " + email);
                return;
            }

            // Crear nuevo usuario con password encriptada
            User user = new User(username, email, passwordEncoder.encode(password), role);
            userRepository.save(user);
            System.out.println("✅ Usuario creado: " + username + " (" + role + ") - " + description);

        } catch (Exception e) {
            System.err.println("❌ Error creando usuario " + username + ": " + e.getMessage());
        }
    }
}