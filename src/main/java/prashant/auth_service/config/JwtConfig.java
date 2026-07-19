package prashant.auth_service.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import prashant.auth_service.service.JwtService;

@Configuration
@RequiredArgsConstructor
public class JwtConfig {

    private final JwtService jwtService;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(jwtService.getPublicKey()).build();
    }
}
