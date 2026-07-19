package prashant.auth_service.config;

public class JwtKeyInitializationException extends RuntimeException {
    public JwtKeyInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
