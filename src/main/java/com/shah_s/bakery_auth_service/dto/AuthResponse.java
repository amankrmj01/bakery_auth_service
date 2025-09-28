package com.shah_s.bakery_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.shah_s.bakery_auth_service.entity.User;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Setter
@Getter
public class AuthResponse {

    // Getters and Setters
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("token_type")
    private String tokenType = "Bearer";

    @JsonProperty("expires_in")
    private Long expiresIn;

    private UserInfo user;

    // Constructors
    public AuthResponse() {}

    public AuthResponse(String accessToken, String refreshToken, Long expiresIn, UserInfo user) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.user = user;
    }

    // Static factory method
    public static AuthResponse of(String accessToken, String refreshToken, Long expiresIn, User user) {
        return new AuthResponse(accessToken, refreshToken, expiresIn, UserInfo.from(user));
    }

    // Inner class for user information
    @Setter
    @Getter
    public static class UserInfo {
        // Getters and Setters
        private UUID id;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String phone;
        private User.Role role;
        private LocalDateTime createdAt;

        // Static factory method
        public static UserInfo from(User user) {
            UserInfo userInfo = new UserInfo();
            userInfo.id = user.getId();
            userInfo.username = user.getUsername();
            userInfo.email = user.getEmail();
            userInfo.firstName = user.getFirstName();
            userInfo.lastName = user.getLastName();
            userInfo.phone = user.getPhone();
            userInfo.role = user.getRole();
            userInfo.createdAt = user.getCreatedAt();
            return userInfo;
        }

    }
}
