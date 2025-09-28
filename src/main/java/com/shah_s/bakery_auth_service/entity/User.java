package com.shah_s.bakery_auth_service.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_username", columnList = "username")
})
public class User {

    // Getters and Setters
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 50)
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @Column(unique = true, nullable = false, length = 100)
    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @Column(nullable = false)
    @NotBlank(message = "Password is required")
    private String password;

    @Column(name = "first_name", length = 50)
    @Size(max = 50, message = "First name must not exceed 50 characters")
    private String firstName;

    @Column(name = "last_name", length = 50)
    @Size(max = 50, message = "Last name must not exceed 50 characters")
    private String lastName;

    @Column(length = 15)
    @Size(max = 15, message = "Phone number must not exceed 15 characters")
    private String phone;

    @Column(columnDefinition = "TEXT")
    private String address;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.USER;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "email_verified")
    private Boolean emailVerified = false;

    @Column(name = "login_attempts")
    private Integer loginAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Constructors
    public User() {}

    public User(String username, String email, String password, String firstName, String lastName) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    // Utility Methods
    public String getFullName() {
        StringBuilder fullName = new StringBuilder();
        if (firstName != null) fullName.append(firstName);
        if (lastName != null) {
            if (!fullName.isEmpty()) fullName.append(" ");
            fullName.append(lastName);
        }
        return !fullName.isEmpty() ? fullName.toString() : username;
    }

    public boolean isAccountLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE && !isAccountLocked();
    }

    // Enums
    public enum Role {
        USER, ADMIN, BAKER
    }

    public enum UserStatus {
        ACTIVE, INACTIVE, LOCKED, PENDING_VERIFICATION
    }
}
