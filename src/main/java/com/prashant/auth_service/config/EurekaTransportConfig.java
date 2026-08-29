package com.prashant.auth_service.config;

import org.springframework.cloud.netflix.eureka.http.EurekaClientHttpRequestFactorySupplier;
import org.springframework.cloud.netflix.eureka.http.RestClientDiscoveryClientOptionalArgs;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * The Eureka HTTP client picks up any {@code RestClient.Builder} bean in the
 * context to build its transport. Because auth-service exposes a
 * load-balanced {@code RestClient.Builder} (see {@link RestClientConfig}),
 * Eureka's requests to the registry would otherwise be sent through the
 * load balancer, which treats {@code localhost} in the defaultZone URL as a
 * service id and fails with "No instances available for localhost".
 *
 * <p>Providing our own {@link RestClientDiscoveryClientOptionalArgs} makes
 * Eureka use a plain {@link RestClient} while the load-balanced builder
 * remains available for service-to-service calls.
 */
@Configuration
public class EurekaTransportConfig {

    @Bean
    public RestClientDiscoveryClientOptionalArgs eurekaRestClientOptionalArgs(
            EurekaClientHttpRequestFactorySupplier eurekaClientHttpRequestFactorySupplier) {
        return new RestClientDiscoveryClientOptionalArgs(eurekaClientHttpRequestFactorySupplier,
                RestClient::builder);
    }
}