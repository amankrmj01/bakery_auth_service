package com.shah_s.bakery_auth_service.service;

import com.shah_s.bakery_auth_service.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    // Get signing key
    private SecretKey getSigningKey() {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Generate access token for user
    public String generateAccessToken(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId().toString());
        extraClaims.put("role", user.getRole().toString());
        extraClaims.put("email", user.getEmail());
        extraClaims.put("fullName", user.getFullName());
        extraClaims.put("tokenType", "ACCESS");

        return generateToken(extraClaims, user.getUsername(), jwtExpiration);
    }

    // Generate refresh token for user
    public String generateRefreshToken(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId().toString());
        extraClaims.put("tokenType", "REFRESH");

        return generateToken(extraClaims, user.getUsername(), refreshExpiration);
    }

    // Generate token with custom claims (FIXED - No deprecation)
    private String generateToken(Map<String, Object> extraClaims, String subject, Long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .claims(extraClaims)                    // ✅ NEW: replaces setClaims()
                .subject(subject)                       // ✅ NEW: replaces setSubject()
                .issuedAt(now)                         // ✅ NEW: replaces setIssuedAt()
                .expiration(expiryDate)                // ✅ NEW: replaces setExpiration()
                .issuer("bakery-auth-service")         // ✅ NEW: replaces setIssuer()
                .signWith(getSigningKey())             // ✅ NEW: no algorithm needed
                .compact();
    }

    // Extract username from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract user ID from token
    public UUID extractUserId(String token) {
        String userIdStr = extractClaim(token, claims -> claims.get("userId", String.class));
        return userIdStr != null ? UUID.fromString(userIdStr) : null;
    }

    // Extract user role from token
    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    // Extract email from token
    public String extractEmail(String token) {
        return extractClaim(token, claims -> claims.get("email", String.class));
    }

    // Extract token type
    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("tokenType", String.class));
    }

    // Extract expiration date
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract any claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from token (FIXED - No deprecation)
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()                        // ✅ FIXED: Use parser() not parserBuilder()
                    .verifyWith(getSigningKey())        // ✅ NEW: replaces setSigningKey()
                    .build()
                    .parseSignedClaims(token)           // ✅ NEW: replaces parseClaimsJws()
                    .getPayload();                      // ✅ NEW: replaces getBody()
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token is expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
            throw e;
        } catch (SecurityException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            logger.error("JWT token compact of handler are invalid: {}", e.getMessage());
            throw e;
        }
    }

    // Check if token is expired
    public Boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    // Validate token against user details
    public Boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    // Validate token format and signature (FIXED - No deprecation)
    public Boolean validateToken(String token) {
        try {
            Jwts.parser()                               // ✅ FIXED: Use parser() not parserBuilder()
                    .verifyWith(getSigningKey())        // ✅ NEW: replaces setSigningKey()
                    .build()
                    .parseSignedClaims(token);          // ✅ NEW: replaces parseClaimsJws()
            return true;
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    // Check if token is access token
    public Boolean isAccessToken(String token) {
        try {
            String tokenType = extractTokenType(token);
            return "ACCESS".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    // Check if token is refresh token
    public Boolean isRefreshToken(String token) {
        try {
            String tokenType = extractTokenType(token);
            return "REFRESH".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    // Get token expiration time in seconds
    public Long getExpirationTime() {
        return jwtExpiration / 1000; // Convert to seconds
    }

    // Get refresh token expiration time in seconds
    public Long getRefreshExpirationTime() {
        return refreshExpiration / 1000; // Convert to seconds
    }

    // Extract token from Authorization header
    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    // Get remaining time until token expires (in seconds)
    public Long getRemainingExpirationTime(String token) {
        try {
            Date expiration = extractExpiration(token);
            long remainingTime = expiration.getTime() - System.currentTimeMillis();
            return Math.max(0, remainingTime / 1000); // Convert to seconds
        } catch (Exception e) {
            return 0L;
        }
    }
}
