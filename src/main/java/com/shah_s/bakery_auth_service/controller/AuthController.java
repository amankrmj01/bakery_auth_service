package com.shah_s.bakery_auth_service.controller;

import com.shah_s.bakery_auth_service.dto.AuthResponse;
import com.shah_s.bakery_auth_service.dto.LoginRequest;
import com.shah_s.bakery_auth_service.dto.RegisterRequest;
import com.shah_s.bakery_auth_service.exception.AuthException;
import com.shah_s.bakery_auth_service.service.AuthService;
import com.shah_s.bakery_auth_service.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    final private AuthService authService;

    final private JwtService jwtService;

    public AuthController(AuthService authService, JwtService jwtService) {
        this.authService = authService;
        this.jwtService = jwtService;
    }

    // User Registration
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) throws AuthException {
        logger.info("Registration request received for username: {}", request.getUsername());

        AuthResponse response = authService.register(request);

        logger.info("Registration successful for username: {}", request.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // User Login
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) throws AuthException {
        logger.info("Login request received for user: {}", request.getUsernameOrEmail());

        AuthResponse response = authService.login(request);

        logger.info("Login successful for user: {}", request.getUsernameOrEmail());
        return ResponseEntity.ok(response);
    }

    // Refresh Token
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(HttpServletRequest request) throws AuthException {
        logger.info("Token refresh request received");

        String authHeader = request.getHeader("Authorization");
        String refreshToken = jwtService.extractTokenFromHeader(authHeader);

        if (refreshToken == null) {
            logger.warn("No refresh token provided in Authorization header");
            return ResponseEntity.badRequest().build();
        }

        AuthResponse response = authService.refreshToken(refreshToken);

        logger.info("Token refresh successful");
        return ResponseEntity.ok(response);
    }

    // Alternative refresh token endpoint (from request body)
    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshTokenFromBody(@RequestBody Map<String, String> request) throws AuthException {
        logger.info("Token refresh request received (from body)");

        String refreshToken = request.get("refreshToken");
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            logger.warn("No refresh token provided in request body");
            return ResponseEntity.badRequest().build();
        }

        AuthResponse response = authService.refreshToken(refreshToken);

        logger.info("Token refresh successful (from body)");
        return ResponseEntity.ok(response);
    }

    // Validate Token (for other microservices)
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(HttpServletRequest request) {
        logger.debug("Token validation request received");

        String authHeader = request.getHeader("Authorization");
        String token = jwtService.extractTokenFromHeader(authHeader);

        if (token == null) {
            logger.warn("No token provided for validation");
            return ResponseEntity.badRequest().body(createErrorResponse("No token provided"));
        }

        AuthService.TokenValidationResponse validation = authService.validateToken(token);

        Map<String, Object> response = new HashMap<>();
        response.put("valid", validation.isValid());
        response.put("message", validation.getMessage());

        if (validation.isValid()) {
            response.put("userId", validation.getUserId());
            response.put("username", validation.getUsername());
            response.put("email", validation.getEmail());
            response.put("role", validation.getRole());
            logger.debug("Token validation successful for user: {}", validation.getUsername());
        } else {
            logger.debug("Token validation failed: {}", validation.getMessage());
        }

        return ResponseEntity.ok(response);
    }

    // Alternative validate token endpoint (from request body)
    @PostMapping("/validate-token")
    public ResponseEntity<Map<String, Object>> validateTokenFromBody(@RequestBody Map<String, String> request) {
        logger.debug("Token validation request received (from body)");

        String token = request.get("token");
        if (token == null || token.trim().isEmpty()) {
            logger.warn("No token provided for validation");
            return ResponseEntity.badRequest().body(createErrorResponse("No token provided"));
        }

        AuthService.TokenValidationResponse validation = authService.validateToken(token);

        Map<String, Object> response = new HashMap<>();
        response.put("valid", validation.isValid());
        response.put("message", validation.getMessage());

        if (validation.isValid()) {
            response.put("userId", validation.getUserId());
            response.put("username", validation.getUsername());
            response.put("email", validation.getEmail());
            response.put("role", validation.getRole());
            logger.debug("Token validation successful for user: {}", validation.getUsername());
        } else {
            logger.debug("Token validation failed: {}", validation.getMessage());
        }

        return ResponseEntity.ok(response);
    }

    // Logout
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) {
        logger.info("Logout request received");

        String authHeader = request.getHeader("Authorization");
        String token = jwtService.extractTokenFromHeader(authHeader);

        if (token != null) {
            authService.logout(token);
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "Logout successful");

        logger.info("Logout processed successfully");
        return ResponseEntity.ok(response);
    }

    // Change Password
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest) throws AuthException {

        logger.info("Password change request received");

        String authHeader = httpRequest.getHeader("Authorization");
        String token = jwtService.extractTokenFromHeader(authHeader);

        if (token == null) {
            return ResponseEntity.badRequest().body(createErrorResponse("Authentication required"));
        }

        UUID userId = jwtService.extractUserId(token);
        String currentPassword = request.get("currentPassword");
        String newPassword = request.get("newPassword");

        if (currentPassword == null || newPassword == null) {
            return ResponseEntity.badRequest().body(createErrorResponse("Current password and new password are required"));
        }

        authService.changePassword(userId, currentPassword, newPassword);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "Password changed successfully");

        logger.info("Password change successful for user ID: {}", userId);
        return ResponseEntity.ok(response);
    }

    // Verify Email
    @PostMapping("/verify-email/{userId}")
    public ResponseEntity<Map<String, String>> verifyEmail(@PathVariable UUID userId) throws AuthException {
        logger.info("Email verification request received for user ID: {}", userId);

        authService.verifyEmail(userId);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Email verified successfully");

        logger.info("Email verification successful for user ID: {}", userId);
        return ResponseEntity.ok(response);
    }

    // Health check endpoint
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "bakery-auth-service");
        response.put("timestamp", java.time.LocalDateTime.now().toString());

        return ResponseEntity.ok(response);
    }

    // Get current user info (from token)
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(HttpServletRequest request) {
        logger.debug("Current user info request received");

        String authHeader = request.getHeader("Authorization");
        String token = jwtService.extractTokenFromHeader(authHeader);

        if (token == null) {
            return ResponseEntity.badRequest().body(createErrorResponse("Authentication required"));
        }

        AuthService.TokenValidationResponse validation = authService.validateToken(token);

        if (!validation.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("Invalid token"));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("userId", validation.getUserId());
        response.put("username", validation.getUsername());
        response.put("email", validation.getEmail());
        response.put("role", validation.getRole());

        return ResponseEntity.ok(response);
    }

    // Utility method to create error responses
    private Map<String, Object> createErrorResponse(String message) {
        Map<String, Object> error = new HashMap<>();
        error.put("error", true);
        error.put("message", message);
        error.put("timestamp", java.time.LocalDateTime.now().toString());
        return error;
    }
}
