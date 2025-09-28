package com.shah_s.bakery_auth_service.repository;

import com.shah_s.bakery_auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Find user by username
    Optional<User> findByUsername(String username);

    // Find user by email
    Optional<User> findByEmail(String email);

    // Find user by username or email (for login)
    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);

    // Check if username exists
    boolean existsByUsername(String username);

    // Check if email exists
    boolean existsByEmail(String email);

    // Find users by role
    List<User> findByRole(User.Role role);

    // Find users by status
    List<User> findByStatus(User.UserStatus status);

    // Find active users
    @Query("SELECT u FROM User u WHERE u.status = 'ACTIVE' AND (u.lockedUntil IS NULL OR u.lockedUntil < CURRENT_TIMESTAMP)")
    List<User> findActiveUsers();

    // Find locked users
    @Query("SELECT u FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil > CURRENT_TIMESTAMP")
    List<User> findLockedUsers();

    // Update login attempts
    @Modifying
    @Query("UPDATE User u SET u.loginAttempts = :attempts WHERE u.id = :userId")
    void updateLoginAttempts(@Param("userId") UUID userId, @Param("attempts") Integer attempts);

    // Update last login time
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") UUID userId, @Param("lastLogin") LocalDateTime lastLogin);

    // Lock user account
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :lockedUntil, u.loginAttempts = :attempts WHERE u.id = :userId")
    void lockUserAccount(@Param("userId") UUID userId, @Param("lockedUntil") LocalDateTime lockedUntil, @Param("attempts") Integer attempts);

    // Unlock user account
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = NULL, u.loginAttempts = 0 WHERE u.id = :userId")
    void unlockUserAccount(@Param("userId") UUID userId);

    // Update email verification status
    @Modifying
    @Query("UPDATE User u SET u.emailVerified = :verified WHERE u.id = :userId")
    void updateEmailVerificationStatus(@Param("userId") UUID userId, @Param("verified") Boolean verified);

    // Find users created between dates
    @Query("SELECT u FROM User u WHERE u.createdAt BETWEEN :startDate AND :endDate")
    List<User> findUsersCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    // Search users by name or email
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<User> searchUsers(@Param("searchTerm") String searchTerm);

    // Count users by role
    @Query("SELECT COUNT(u) FROM User u WHERE u.role = :role")
    Long countByRole(@Param("role") User.Role role);

    // Count active users
    @Query("SELECT COUNT(u) FROM User u WHERE u.status = 'ACTIVE' AND (u.lockedUntil IS NULL OR u.lockedUntil < CURRENT_TIMESTAMP)")
    Long countActiveUsers();

    // Find users with failed login attempts
    @Query("SELECT u FROM User u WHERE u.loginAttempts >= :maxAttempts")
    List<User> findUsersWithFailedLoginAttempts(@Param("maxAttempts") Integer maxAttempts);

    // Find users who haven't logged in for a specific period
    @Query("SELECT u FROM User u WHERE u.lastLogin < :cutoffDate OR u.lastLogin IS NULL")
    List<User> findInactiveUsers(@Param("cutoffDate") LocalDateTime cutoffDate);

    // Find unverified users
    @Query("SELECT u FROM User u WHERE u.emailVerified = false")
    List<User> findUnverifiedUsers();

    // Custom query to find users by partial phone number
    @Query("SELECT u FROM User u WHERE u.phone LIKE CONCAT('%', :phoneNumber, '%')")
    List<User> findByPhoneContaining(@Param("phoneNumber") String phoneNumber);

    // Get user statistics
    @Query("SELECT " +
            "COUNT(u) as totalUsers, " +
            "COUNT(CASE WHEN u.status = 'ACTIVE' THEN 1 END) as activeUsers, " +
            "COUNT(CASE WHEN u.emailVerified = true THEN 1 END) as verifiedUsers, " +
            "COUNT(CASE WHEN u.role = 'ADMIN' THEN 1 END) as adminUsers " +
            "FROM User u")
    Object[] getUserStatistics();
}
