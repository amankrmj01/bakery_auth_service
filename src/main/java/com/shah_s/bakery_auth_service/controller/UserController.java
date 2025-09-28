package com.shah_s.bakery_auth_service.controller;

import com.shah_s.bakery_auth_service.dto.RegisterRequest;
import com.shah_s.bakery_auth_service.dto.UserResponse;
import com.shah_s.bakery_auth_service.entity.User;
import com.shah_s.bakery_auth_service.exception.AuthException;
import com.shah_s.bakery_auth_service.service.JwtService;
import com.shah_s.bakery_auth_service.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    // Get user profile
    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getUserProfile(HttpServletRequest request) throws AuthException {
        logger.info("Get user profile request received");

        UUID userId = extractUserIdFromToken(request);
        if (userId == null) {
            return ResponseEntity.badRequest().build();
        }

        UserResponse userResponse = userService.getUserProfile(userId);

        logger.info("User profile retrieved for user ID: {}", userId);
        return ResponseEntity.ok(userResponse);
    }

    // Update user profile
    @PutMapping("/profile")
    public ResponseEntity<UserResponse> updateUserProfile(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) throws AuthException {

        logger.info("Update user profile request received");

        UUID userId = extractUserIdFromToken(httpRequest);
        if (userId == null) {
            return ResponseEntity.badRequest().build();
        }

        UserResponse userResponse = userService.updateUserProfile(userId, request);

        logger.info("User profile updated for user ID: {}", userId);
        return ResponseEntity.ok(userResponse);
    }

    // Get user by ID (Admin or self only)
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUserById(
            @PathVariable UUID userId,
            HttpServletRequest request) throws AuthException {

        logger.info("Get user by ID request received for user ID: {}", userId);

        UUID requestingUserId = extractUserIdFromToken(request);
        String requestingUserRole = extractRoleFromToken(request);

        // Allow if requesting own profile or if admin
        if (!userId.equals(requestingUserId) && (requestingUserRole == null || !requestingUserRole.equalsIgnoreCase("ADMIN"))) {
            return ResponseEntity.status(403).build(); // Forbidden
        }

        UserResponse userResponse = userService.getUserProfile(userId);

        logger.info("User retrieved for user ID: {}", userId);
        return ResponseEntity.ok(userResponse);
    }

    // Admin endpoints
    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        logger.info("Get all users request received (admin)");

        List<UserResponse> users = userService.getAllUsers();

        logger.info("All users retrieved, count: {}", users.size());
        return ResponseEntity.ok(users);
    }

    // Search users (Admin only)
    @GetMapping("/admin/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> searchUsers(@RequestParam String query) {
        logger.info("Search users request received (admin) with query: {}", query);

        List<UserResponse> users = userService.searchUsers(query);

        logger.info("User search completed, results: {}", users.size());
        return ResponseEntity.ok(users);
    }

    // Get users by role (Admin only)
    @GetMapping("/admin/role/{role}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponse>> getUsersByRole(@PathVariable String role) {
        logger.info("Get users by role request received (admin) for role: {}", role);

        try {
            User.Role userRole = User.Role.valueOf(role.toUpperCase());
            List<UserResponse> users = userService.getUsersByRole(userRole);

            logger.info("Users by role retrieved, count: {}", users.size());
            return ResponseEntity.ok(users);
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid role requested: {}", role);
            return ResponseEntity.badRequest().build();
        }
    }

    // Update user role (Admin only)
    @PutMapping("/admin/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> updateUserRole(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {

        logger.info("Update user role request received (admin) for user ID: {}", userId);

        String roleStr = request.get("role");
        if (roleStr == null) {
            return ResponseEntity.badRequest().build();
        }

        try {
            User.Role role = User.Role.valueOf(roleStr.toUpperCase());
            userService.updateUserRole(userId, role);

            Map<String, String> response = new HashMap<>();
            response.put("message", "User role updated successfully");

            logger.info("User role updated to {} for user ID: {}", role, userId);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException | AuthException e) {
            logger.warn("Invalid role requested: {}", roleStr);
            return ResponseEntity.badRequest().build();
        }
    }

    // Update user status (Admin only)
    @PutMapping("/admin/{userId}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> updateUserStatus(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {

        logger.info("Update user status request received (admin) for user ID: {}", userId);

        String statusStr = request.get("status");
        if (statusStr == null) {
            return ResponseEntity.badRequest().build();
        }

        try {
            User.UserStatus status = User.UserStatus.valueOf(statusStr.toUpperCase());
            userService.updateUserStatus(userId, status);

            Map<String, String> response = new HashMap<>();
            response.put("message", "User status updated successfully");

            logger.info("User status updated to {} for user ID: {}", status, userId);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException | AuthException e) {
            logger.warn("Invalid status requested: {}", statusStr);
            return ResponseEntity.badRequest().build();
        }
    }

    // Unlock user account (Admin only)
    @PostMapping("/admin/{userId}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> unlockUserAccount(@PathVariable UUID userId) throws AuthException {
        logger.info("Unlock user account request received (admin) for user ID: {}", userId);

        userService.unlockAccount(userId);

        Map<String, String> response = new HashMap<>();
        response.put("message", "User account unlocked successfully");

        logger.info("User account unlocked for user ID: {}", userId);
        return ResponseEntity.ok(response);
    }

    // Delete user (Admin only)
    @DeleteMapping("/admin/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> deleteUser(@PathVariable UUID userId) throws AuthException {
        logger.info("Delete user request received (admin) for user ID: {}", userId);

        userService.deleteUser(userId);

        Map<String, String> response = new HashMap<>();
        response.put("message", "User deleted successfully");

        logger.info("User deleted for user ID: {}", userId);
        return ResponseEntity.ok(response);
    }

    // Get user statistics (Admin only)
    @GetMapping("/admin/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Long>> getUserStatistics() {
        logger.info("Get user statistics request received (admin)");

        Map<String, Long> statistics = userService.getUserStatistics();

        logger.info("User statistics retrieved");
        return ResponseEntity.ok(statistics);
    }

    // Utility methods
    private UUID extractUserIdFromToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        String token = jwtService.extractTokenFromHeader(authHeader);

        if (token == null || !jwtService.validateToken(token)) {
            return null;
        }

        return jwtService.extractUserId(token);
    }

    private String extractRoleFromToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        String token = jwtService.extractTokenFromHeader(authHeader);

        if (token == null || !jwtService.validateToken(token)) {
            return null;
        }

        return jwtService.extractRole(token);
    }
}
