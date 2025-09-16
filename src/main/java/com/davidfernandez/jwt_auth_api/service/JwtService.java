package com.davidfernandez.jwt_auth_api.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Servicio para manejar tokens JWT (JSON Web Tokens)
 *
 * Responsabilidades:
 * - Generar tokens JWT cuando el usuario hace login
 * - Validar tokens JWT en cada petición protegida
 * - Extraer información del token (username, fecha de expiración, etc.)
 * - Verificar si un token ha expirado
 */
@Service
public class JwtService {

    // Clave secreta para firmar los tokens (viene de application.yml)
    // En producción NUNCA debe estar en el código - usar variables de entorno
    @Value("${jwt.secret}")
    private String secretKey;

    // Tiempo de expiración del token en milisegundos (viene de application.yml)
    // Por defecto: 24 horas = 86400000 ms
    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Genera un token JWT para un usuario autenticado
     *
     * @param userDetails información del usuario (username, roles, etc.)
     * @return String token JWT completo
     *
     * Ejemplo de uso: String token = jwtService.generateToken(user);
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Genera un token JWT con claims adicionales
     *
     * @param extraClaims información extra a incluir en el token (opcional)
     * @param userDetails información del usuario
     * @return String token JWT
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Construye el token JWT con toda la información necesaria
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts
                .builder()
                .setClaims(extraClaims)           // Claims adicionales (si los hay)
                .setSubject(userDetails.getUsername())  // "sub": username del usuario
                .setIssuedAt(new Date(System.currentTimeMillis()))  // "iat": cuándo se creó
                .setExpiration(new Date(System.currentTimeMillis() + expiration))  // "exp": cuándo expira
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)  // Firmar con clave secreta
                .compact();  // Convertir a string
    }

    /**
     * Extrae el username del token JWT
     *
     * @param token el token JWT
     * @return String username del usuario
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae la fecha de expiración del token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrae un claim específico del token usando una función
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todos los claims (datos) del token JWT
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()  // Cambio: usar parser() en lugar de parserBuilder()
                .verifyWith(getSignInKey())  // Cambio: verifyWith en lugar de setSigningKey
                .build()
                .parseSignedClaims(token)  // Cambio: parseSignedClaims en lugar de parseClaimsJws
                .getPayload();  // Cambio: getPayload en lugar de getBody
    }

    /**
     * Verifica si un token es válido para un usuario específico
     *
     * @param token token a validar
     * @param userDetails usuario contra el que validar
     * @return true si el token es válido, false si no
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Verifica si el token ha expirado
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Obtiene la clave de firma para los tokens
     * Convierte el string secretKey en una clave criptográfica válida
     */
    private SecretKey getSignInKey() {
        byte[] keyBytes = secretKey.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);  // Cambio: hmacShaKeyFor en lugar de hmacShaFor
    }
}