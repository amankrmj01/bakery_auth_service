# Bakery Auth Service

## Overview
Handles user registration, authentication, and authorization using OAuth2 and JWT tokens.

## Features
- User sign-up and login
- OAuth2 Authorization server
- JWT token issuance and validation
- Role-based access control (RBAC)

## Dependencies
- Spring Security OAuth2
- Spring Data JPA
- Token Store (JPA or Redis)
- Spring Boot Actuator

## Key Endpoints
- `/api/auth/signup`
- `/api/auth/login`
- Token endpoints under `/oauth/`

## Running
./gradlew bootRun

Runs on port 8081 by default.

## Documentation
Swagger UI: `http://localhost:8081/swagger-ui.html`

---
