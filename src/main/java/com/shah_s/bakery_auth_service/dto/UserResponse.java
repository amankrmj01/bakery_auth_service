package com.shah_s.bakery_auth_service.dto;

import com.shah_s.bakery_auth_service.entity.User;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Setter
@Getter
public class UserResponse {

    // Getters and Setters
    private UUID id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String phone;
    private String address;
    private User.Role role;
    private User.UserStatus status;
    private Boolean emailVerified;
    private LocalDateTime lastLogin;
    private LocalDateTime createdAt;

    // Constructors
    public UserResponse() {}

    // Static factory method
    public static UserResponse from(User user) {
        UserResponse response = new UserResponse();
        response.id = user.getId();
        response.username = user.getUsername();
        response.email = user.getEmail();
        response.firstName = user.getFirstName();
        response.lastName = user.getLastName();
        response.phone = user.getPhone();
        response.address = user.getAddress();
        response.role = user.getRole();
        response.status = user.getStatus();
        response.emailVerified = user.getEmailVerified();
        response.lastLogin = user.getLastLogin();
        response.createdAt = user.getCreatedAt();
        return response;
    }

}
