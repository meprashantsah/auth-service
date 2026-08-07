package com.prashant.auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Auth Service Application - JWT Authentication & Authorization Microservice.
 *
 * Responsibilities:
 * - User registration & login
 * - JWT token generation (Access + Refresh) using RS256
 * - Token validation & introspection
 * - Role-Based Access Control (RBAC) management
 * - Token refresh & revocation (logout)
 * - Password encryption with BCrypt
 */
@SpringBootApplication
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
