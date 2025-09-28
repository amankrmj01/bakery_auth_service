package com.shah_s.bakery_auth_service.service;

import com.shah_s.bakery_auth_service.dto.AuthResponse;
import com.shah_s.bakery_auth_service.dto.LoginRequest;
import com.shah_s.bakery_auth_service.dto.RegisterRequest;
import com.shah_s.bakery_auth_service.entity.User;
import com.shah_s.bakery_auth_service.exception.AuthException;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    final private UserService userService;

    final private JwtService jwtService;

    public AuthService(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    // User registration
    public AuthResponse register(RegisterRequest request) throws AuthException {
        logger.info("Processing registration for username: {}", request.getUsername());

        try {
            // Create user through UserService
            User user = userService.createUser(request);

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            Long expiresIn = jwtService.getExpirationTime();

            logger.info("Registration successful for user: {}", user.getUsername());

            return AuthResponse.of(accessToken, refreshToken, expiresIn, user);

        } catch (Exception e) {
            logger.error("Registration failed for username: {} - {}", request.getUsername(), e.getMessage());
            throw new AuthException("Registration failed: " + e.getMessage());
        }
    }

    // User login
    public AuthResponse login(LoginRequest request) throws AuthException {
        logger.info("Processing login for user: {}", request.getUsernameOrEmail());

        try {
            // Check if account is locked
            if (userService.isAccountLocked(request.getUsernameOrEmail())) {
                throw new AuthException("Account is locked due to too many failed login attempts. Please try again later.");
            }

            // Find user by username or email
            Optional<User> userOptional = userService.findByUsernameOrEmail(request.getUsernameOrEmail());

            if (userOptional.isEmpty()) {
                // Record failed attempt even for non-existent user (prevent user enumeration)
                userService.recordFailedLogin(request.getUsernameOrEmail());
                throw new AuthException("Invalid credentials");
            }

            User user = userOptional.get();

            // Check if user is active
            if (!user.isActive()) {
                throw new AuthException("Account is not active. Please contact support.");
            }

            // Validate password
            if (!userService.validateCredentials(request.getUsernameOrEmail(), request.getPassword())) {
                // Record failed login attempt
                userService.recordFailedLogin(request.getUsernameOrEmail());
                throw new AuthException("Invalid credentials");
            }

            // Record successful login
            userService.recordSuccessfulLogin(user.getId());

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            Long expiresIn = jwtService.getExpirationTime();

            logger.info("Login successful for user: {}", user.getUsername());

            return AuthResponse.of(accessToken, refreshToken, expiresIn, user);

        } catch (AuthException e) {
            logger.warn("Login failed for user: {} - {}", request.getUsernameOrEmail(), e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during login for user: {} - {}", request.getUsernameOrEmail(), e.getMessage());
            throw new AuthException("Login failed due to an unexpected error");
        }
    }

    // Refresh token
    public AuthResponse refreshToken(String refreshToken) throws AuthException {
        logger.info("Processing token refresh");

        try {
            // Validate refresh token format
            if (!jwtService.validateToken(refreshToken)) {
                throw new AuthException("Invalid refresh token");
            }

            // Check if it's actually a refresh token
            if (!jwtService.isRefreshToken(refreshToken)) {
                throw new AuthException("Token is not a refresh token");
            }

            // Check if refresh token is expired
            if (jwtService.isTokenExpired(refreshToken)) {
                throw new AuthException("Refresh token is expired");
            }

            // Extract username from refresh token
            String username = jwtService.extractUsername(refreshToken);

            // Find user
            Optional<User> userOptional = userService.findByUsername(username);
            if (userOptional.isEmpty()) {
                throw new AuthException("User not found");
            }

            User user = userOptional.get();

            // Check if user is still active
            if (!user.isActive()) {
                throw new AuthException("Account is not active");
            }

            // Generate new tokens
            String newAccessToken = jwtService.generateAccessToken(user);
            String newRefreshToken = jwtService.generateRefreshToken(user);
            Long expiresIn = jwtService.getExpirationTime();

            logger.info("Token refresh successful for user: {}", user.getUsername());

            return AuthResponse.of(newAccessToken, newRefreshToken, expiresIn, user);

        } catch (AuthException e) {
            logger.warn("Token refresh failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during token refresh: {}", e.getMessage());
            throw new AuthException("Token refresh failed");
        }
    }

    // Validate token (for other microservices)
    public TokenValidationResponse validateToken(String token) {
        logger.debug("Validating token");

        try {
            // Basic token validation
            if (!jwtService.validateToken(token)) {
                return TokenValidationResponse.invalid("Invalid token");
            }

            // Check if it's an access token
            if (!jwtService.isAccessToken(token)) {
                return TokenValidationResponse.invalid("Not an access token");
            }

            // Extract user information
            String username = jwtService.extractUsername(token);
            UUID userId = jwtService.extractUserId(token);
            String role = jwtService.extractRole(token);
            String email = jwtService.extractEmail(token);

            // Verify user still exists and is active
            Optional<User> userOptional = userService.findById(userId);
            if (userOptional.isEmpty()) {
                return TokenValidationResponse.invalid("User not found");
            }

            User user = userOptional.get();
            if (!user.isActive()) {
                return TokenValidationResponse.invalid("User account is not active");
            }

            logger.debug("Token validation successful for user: {}", username);

            return TokenValidationResponse.valid(userId, username, email, role);

        } catch (Exception e) {
            logger.error("Token validation error: {}", e.getMessage());
            return TokenValidationResponse.invalid("Token validation failed");
        }
    }

    // Logout (optional - for token blacklisting if needed)
    public void logout(String token) {
        logger.info("Processing logout");

        try {
            String username = jwtService.extractUsername(token);
            logger.info("Logout successful for user: {}", username);

            // In a production system, you might want to blacklist the token here
            // For now, we'll just log the logout

        } catch (Exception e) {
            logger.warn("Logout processing failed: {}", e.getMessage());
        }
    }

    // Change password (authenticated user)
    public void changePassword(UUID userId, String currentPassword, String newPassword) throws AuthException {
        logger.info("Processing password change for user ID: {}", userId);

        try {
            userService.updatePassword(userId, currentPassword, newPassword);
            logger.info("Password change successful for user ID: {}", userId);

        } catch (Exception e) {
            logger.error("Password change failed for user ID: {} - {}", userId, e.getMessage());
            throw new AuthException("Password change failed: " + e.getMessage());
        }
    }

    // Verify email (if you implement email verification)
    public void verifyEmail(UUID userId) throws AuthException {
        logger.info("Processing email verification for user ID: {}", userId);

        try {
            userService.verifyEmail(userId);
            logger.info("Email verification successful for user ID: {}", userId);

        } catch (Exception e) {
            logger.error("Email verification failed for user ID: {} - {}", userId, e.getMessage());
            throw new AuthException("Email verification failed");
        }
    }

    // Inner class for token validation response
    @Getter
    public static class TokenValidationResponse {
        // Getters
        private final boolean valid;
        private final String message;
        private final UUID userId;
        private final String username;
        private final String email;
        private final String role;

        private TokenValidationResponse(boolean valid, String message, UUID userId, String username, String email, String role) {
            this.valid = valid;
            this.message = message;
            this.userId = userId;
            this.username = username;
            this.email = email;
            this.role = role;
        }

        public static TokenValidationResponse valid(UUID userId, String username, String email, String role) {
            return new TokenValidationResponse(true, "Valid", userId, username, email, role);
        }

        public static TokenValidationResponse invalid(String message) {
            return new TokenValidationResponse(false, message, null, null, null, null);
        }

    }
}
