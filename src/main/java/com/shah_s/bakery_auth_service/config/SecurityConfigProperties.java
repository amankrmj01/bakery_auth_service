package com.shah_s.bakery_auth_service.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityConfigProperties {
    private Password password = new Password();
    private Login login = new Login();

    @Setter
    @Getter
    public static class Password {
        private int strength;

    }
    @Setter
    @Getter
    public static class Login {
        private int maxAttempts;
        private long lockoutDuration;

    }
}
