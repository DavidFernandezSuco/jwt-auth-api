package com.davidfernandez.jwt_auth_api.repository;

import com.davidfernandez.jwt_auth_api.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface para acceso a datos de usuarios
 *
 * Spring Data JPA automáticamente implementa esta interfaz y proporciona:
 * - Métodos CRUD básicos (save, findById, findAll, delete, etc.)
 * - Query methods personalizados basados en nombres de métodos
 * - Integración automática con transacciones
 *
 * No necesitas escribir implementación - Spring lo hace por ti!
 */
@Repository // Marca como componente de acceso a datos
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Busca un usuario por su username
     * Spring genera automáticamente la query: SELECT * FROM users WHERE username = ?
     *
     * @param username el nombre de usuario a buscar
     * @return Optional<User> - vacío si no encuentra nada, con User si lo encuentra
     *
     * Uso: Optional<User> user = userRepository.findByUsername("juan123");
     */
    Optional<User> findByUsername(String username);

    /**
     * Busca un usuario por su email
     * Spring genera automáticamente: SELECT * FROM users WHERE email = ?
     *
     * @param email el email a buscar
     * @return Optional<User> - vacío si no existe, con User si existe
     *
     * Uso: Optional<User> user = userRepository.findByEmail("juan@example.com");
     */
    Optional<User> findByEmail(String email);

    /**
     * Verifica si existe un usuario con ese username
     * Spring genera: SELECT COUNT(*) > 0 FROM users WHERE username = ?
     *
     * @param username el username a verificar
     * @return true si existe, false si no existe
     *
     * Uso: boolean exists = userRepository.existsByUsername("juan123");
     */
    boolean existsByUsername(String username);

    /**
     * Verifica si existe un usuario con ese email
     * Spring genera: SELECT COUNT(*) > 0 FROM users WHERE email = ?
     *
     * @param email el email a verificar
     * @return true si existe, false si no existe
     *
     * Útil para validar que no se registren emails duplicados
     */
    boolean existsByEmail(String email);
}

/*
 * MÉTODOS QUE HEREDA AUTOMÁTICAMENTE de JpaRepository:
 *
 * - save(User user)                    // Guarda o actualiza usuario
 * - findById(Long id)                  // Busca por ID
 * - findAll()                          // Obtiene todos los usuarios
 * - deleteById(Long id)                // Elimina por ID
 * - delete(User user)                  // Elimina usuario específico
 * - count()                            // Cuenta total de usuarios
 * - existsById(Long id)                // Verifica si existe por ID
 */