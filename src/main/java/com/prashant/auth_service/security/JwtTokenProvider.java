package com.prashant.auth_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JWT Token Provider - Signs and validates JWT tokens using RS256 (RSA + SHA-256).
 *
 * - Access Token: Short-lived (15 min), contains user claims
 * - Refresh Token: Long-lived (7 days), opaque reference stored in DB
 */
@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${jwt.private-key}")
    private String privateKeyString;

    @Value("${jwt.public-key}")
    private String publicKeyString;

    @Value("${jwt.issuer:auth-service}")
    private String issuer;

    @Value("${jwt.audience:api-gateway}")
    private String audience;

    @Value("${jwt.access-token-expiry:900}")
    private long accessTokenExpirySeconds;

    @Value("${jwt.refresh-token-expiry:604800}")
    private long refreshTokenExpirySeconds;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() throws Exception {
        // Load private key
        String privateCleaned = privateKeyString
                .replaceAll("-----(BEGIN|END) [A-Z ]+KEY-----", "")
                .replaceAll("[^A-Za-z0-9+/=]", "");
        byte[] privateDecoded = Base64.getDecoder().decode(privateCleaned);
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateDecoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.privateKey = keyFactory.generatePrivate(privateSpec);

        // Load public key
        String publicCleaned = publicKeyString
                .replaceAll("-----(BEGIN|END) [A-Z ]+KEY-----", "")
                .replaceAll("[^A-Za-z0-9+/=]", "");
        byte[] publicDecoded = Base64.getDecoder().decode(publicCleaned);
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicDecoded);
        this.publicKey = keyFactory.generatePublic(publicSpec);

        log.info("JWT RSA key pair loaded successfully");
    }

    /**
     * Generates an access token for the authenticated user.
     */
    public String generateAccessToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenExpirySeconds, ChronoUnit.SECONDS);

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        String username = authentication.getName();
        String userId = ((UserPrincipal) authentication.getPrincipal()).getId().toString();

        return Jwts.builder()
                .subject(userId)
                .claim("username", username)
                .claim("roles", roles)
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .id(UUID.randomUUID().toString())
                .claim("type", "ACCESS")
                .signWith(privateKey, io.jsonwebtoken.SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Generates a refresh token (JWT format for consistency, but validated against DB).
     */
    public String generateRefreshToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant expiry = now.plus(refreshTokenExpirySeconds, ChronoUnit.SECONDS);

        String userId = ((UserPrincipal) authentication.getPrincipal()).getId().toString();

        return Jwts.builder()
                .subject(userId)
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .id(UUID.randomUUID().toString())
                .claim("type", "REFRESH")
                .signWith(privateKey, io.jsonwebtoken.SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Validates a token and returns its claims.
     */
    public Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer(issuer)
                .requireAudience(audience)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts the JTI (JWT ID) for blacklist checks.
     */
    public String getTokenId(String token) {
        return validateToken(token).getId();
    }

    public String getUserId(String token) {
        return validateToken(token).getSubject();
    }

    public Date getExpiryDate(String token) {
        return validateToken(token).getExpiration();
    }

    public boolean isTokenExpired(String token) {
        try {
            Date expiry = getExpiryDate(token);
            return expiry.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public long getAccessTokenExpirySeconds() {
        return accessTokenExpirySeconds;
    }

    public long getRefreshTokenExpirySeconds() {
        return refreshTokenExpirySeconds;
    }
}
