# JWT Authentication API

[![CI Pipeline](https://github.com/DavidFernandezSuco/jwt-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidFernandezSuco/jwt-auth-api/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.java.net/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.5-brightgreen.svg)](https://spring.io/projects/spring-boot)

## Problem it Solves

JWT-based authentication system with role-based authorization. Demonstrates secure REST API protection with ADMIN/USER roles and stateless authentication.

## Technologies Used

- **Java 21** + **Spring Boot 3.5.5** + **Spring Security**
- **JWT** for stateless authentication
- **H2 Database** (in-memory)
- **Docker** for containerization
- **GitHub Actions** for CI/CD automation
- **Maven** for build management

## How to Run

```bash
# Clone and run with Docker
git clone https://github.com/DavidFernandezSuco/jwt-auth-api.git
cd jwt-auth-api
docker-compose -f docker-compose.dev.yml up --build

# Or run locally
./mvnw spring-boot:run
```

**Test the API:**
```bash
# Get JWT token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Use token to access protected endpoints
curl -H "Authorization: Bearer <token>" http://localhost:8080/admin/test
```

Default users: `admin/admin123` (ADMIN), `user/user123` (USER)

## What I Learned

**Authentication & Security:**
- JWT token lifecycle and validation
- Role-based authorization with Spring Security
- Resolving circular dependency issues in Spring configuration
- BCrypt password hashing

**Containerization:**
- Multi-stage Docker builds for optimized images
- Docker Compose orchestration
- Environment-based configuration

**CI/CD:**
- GitHub Actions pipeline setup
- Automated testing and compilation
- Dependency caching for faster builds

This mini-project showcases fundamental enterprise security patterns while maintaining simplicity for easy setup and testing.