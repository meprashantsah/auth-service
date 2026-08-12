package com.prashant.auth_service.client;

import com.prashant.auth_service.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.UUID;

/**
 * Thin client for the user-service internal API. During registration the
 * auth-service creates the account identity here and the user profile in the
 * user-service in the same flow.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserServiceClient {

    private final RestClient.Builder restClientBuilder;

    @Value("${internal.api-key}")
    private String internalApiKey;

    public void createUserProfile(UUID userId, String username, String displayName, String email) {
        try {
            restClientBuilder.build()
                    .post()
                    .uri("http://user-service/internal/users")
                    .header("X-Internal-Key", internalApiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new CreateUserProfileRequest(userId, username, displayName, email))
                    .retrieve()
                    .toBodilessEntity();
            log.info("User profile created in user-service for: {}", username);
        } catch (RestClientException e) {
            log.error("Failed to create user profile in user-service for: {}", username, e);
            throw new AuthException("Registration failed, please try again later", e);
        }
    }
}