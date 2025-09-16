package com.davidfernandez.jwt_auth_api.entity;

/**
 * Enum que define los roles de usuario en el sistema
 * - USER: Usuario normal con permisos básicos
 * - ADMIN: Administrador con permisos completos
 */
public enum Role {
    USER,   // Rol básico para usuarios normales
    ADMIN   // Rol con privilegios de administración
}