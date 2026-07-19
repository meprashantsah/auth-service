package prashant.auth_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import prashant.auth_service.config.JwtKeyInitializationException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
public class JwtService {

    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final long accessTokenTtlMinutes;
    private final long refreshTokenTtlDays;
    private final String privateKeyPath;
    private final String publicKeyPath;
    private final boolean generateOnMissing;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public JwtService(
            @Value("${jwt.access-token.ttl-minutes:15}") long accessTokenTtlMinutes,
            @Value("${jwt.refresh-token.ttl-days:7}") long refreshTokenTtlDays,
            @Value("${jwt.keys.private-key-path:classpath:keys/jwt-private.pem}") String privateKeyPath,
            @Value("${jwt.keys.public-key-path:classpath:keys/jwt-public.pem}") String publicKeyPath,
            @Value("${jwt.keys.generate-on-missing:true}") boolean generateOnMissing) {
        this.accessTokenTtlMinutes = accessTokenTtlMinutes;
        this.refreshTokenTtlDays = refreshTokenTtlDays;
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
        this.generateOnMissing = generateOnMissing;
    }

    @PostConstruct
    public void init() {
        loadOrGenerateKeys();
    }

    private void loadOrGenerateKeys() {
        try {
            if (privateKeyPath.startsWith(CLASSPATH_PREFIX)) {
                Resource resource = new ClassPathResource(privateKeyPath.substring(CLASSPATH_PREFIX.length()));
                if (resource.exists()) {
                    loadKeysFromClasspath(resource);
                } else if (generateOnMissing) {
                    generateAndStoreKeys();
                } else {
                    throw new IllegalStateException("JWT keys not found at classpath and generation disabled");
                }
            } else {
                File privateFile = new File(privateKeyPath);
                File publicFile = new File(publicKeyPath);
                if (privateFile.exists() && publicFile.exists()) {
                    loadKeysFromFile(privateFile, publicFile);
                } else if (generateOnMissing) {
                    generateAndStoreKeys();
                } else {
                    throw new IllegalStateException("JWT keys not found and generation disabled");
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Failed to initialize JWT keys", e);
            throw new JwtKeyInitializationException("JWT key initialization failed", e);
        }
    }

    private void loadKeysFromClasspath(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privatePem = new String(resource.getInputStream().readAllBytes());
        Resource publicResource = new ClassPathResource(publicKeyPath.substring(CLASSPATH_PREFIX.length()));
        String publicPem = new String(publicResource.getInputStream().readAllBytes());
        parseKeys(privatePem, publicPem);
    }

    private void loadKeysFromFile(File privateFile, File publicFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privatePem = Files.readString(privateFile.toPath());
        String publicPem = Files.readString(publicFile.toPath());
        parseKeys(privatePem, publicPem);
    }

    private void parseKeys(String privatePem, String publicPem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = decodePem(privatePem);
        byte[] publicKeyBytes = decodePem(publicPem);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        log.info("JWT RSA keys loaded successfully");
    }

    private byte[] decodePem(String pem) {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private void generateAndStoreKeys() throws NoSuchAlgorithmException, IOException {
        log.info("Generating new RSA key pair for JWT signing");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, SECURE_RANDOM);
        var keyPair = keyGen.generateKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        File keysDir = new File("./keys");
        keysDir.mkdirs();

        File privateFile = new File(keysDir, "jwt-private.pem");
        File publicFile = new File(keysDir, "jwt-public.pem");

        Files.writeString(privateFile.toPath(), encodeToPem(privateKey.getEncoded(), "PRIVATE KEY"));
        Files.writeString(publicFile.toPath(), encodeToPem(publicKey.getEncoded(), "PUBLIC KEY"));

        log.info("RSA key pair generated and stored at {}", keysDir.getAbsolutePath());
    }

    private String encodeToPem(byte[] bytes, String type) {
        String base64 = Base64.getEncoder().encodeToString(bytes);
        StringBuilder builder = new StringBuilder();
        builder.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            builder.append(base64, i, Math.min(i + 64, base64.length())).append("\n");
        }
        builder.append("-----END ").append(type).append("-----");
        return builder.toString();
    }

    public String generateAccessToken(UUID userId, String username, Set<String> roles) {
        Instant now = Instant.now();
        Instant expiration = now.plus(accessTokenTtlMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
                .subject(userId.toString())
                .claim("username", username)
                .claim("roles", String.join(",", roles))
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public String generateRefreshToken() {
        byte[] bytes = new byte[64];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException _) {
            return false;
        }
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public UUID getUserIdFromToken(String token) {
        Claims claims = parseClaims(token);
        return UUID.fromString(claims.getSubject());
    }

    public String getUsernameFromToken(String token) {
        Claims claims = parseClaims(token);
        return claims.get("username", String.class);
    }

    public Set<String> getRolesFromToken(String token) {
        Claims claims = parseClaims(token);
        String rolesStr = claims.get("roles", String.class);
        return Set.of(rolesStr.split(","));
    }

    public Instant getExpiration(String token) {
        Claims claims = parseClaims(token);
        return claims.getExpiration().toInstant();
    }

    public long getRemainingTtlSeconds(String token) {
        Instant expiration = getExpiration(token);
        Instant now = Instant.now();
        return expiration.isAfter(now) ? expiration.getEpochSecond() - now.getEpochSecond() : 0;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
}