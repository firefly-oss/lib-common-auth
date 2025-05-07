package com.catalis.common.auth.config;

import com.catalis.common.auth.aspect.AccessControlAspect;
import com.catalis.common.auth.filter.AuthContextWebFilter;
import com.catalis.common.auth.service.AccessValidationService;
import com.catalis.common.auth.service.AccessValidatorRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Auto-configuration class for the authentication and authorization components.
 * This class configures Spring Security and enables the aspect-oriented programming (AOP) features.
 */
@Configuration
@EnableAspectJAutoProxy
@ComponentScan(basePackages = {
        "com.catalis.common.auth.service",
        "com.catalis.common.auth.service.validator"
})
public class AuthAutoConfiguration {

    /**
     * Configures the security filter chain.
     * This configuration disables the default Spring Security features since authentication
     * is delegated to the perimeter (Istio/API Gateway).
     *
     * @param http the ServerHttpSecurity to configure
     * @return the configured SecurityWebFilterChain
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)  // Disables HTTP Basic Auth
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)  // Disables form login
                .logout(ServerHttpSecurity.LogoutSpec::disable)        // Disables logout endpoint
                .anonymous(ServerHttpSecurity.AnonymousSpec::disable)  // Disables anonymous authentication
                .requestCache(ServerHttpSecurity.RequestCacheSpec::disable) // Disables request cache
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().permitAll())  // Permit all requests without authentication
                .build();
    }

    /**
     * Creates the AuthContextWebFilter bean if it doesn't exist.
     *
     * @return the AuthContextWebFilter
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthContextWebFilter authContextWebFilter() {
        return new AuthContextWebFilter();
    }

    /**
     * Creates the AccessValidatorRegistry bean if it doesn't exist.
     *
     * @param applicationContext the application context
     * @return the AccessValidatorRegistry
     */
    @Bean
    @ConditionalOnMissingBean
    public AccessValidatorRegistry accessValidatorRegistry(org.springframework.context.ApplicationContext applicationContext) {
        return new AccessValidatorRegistry(applicationContext);
    }

    /**
     * Creates the AccessValidationService bean if it doesn't exist.
     *
     * @param accessValidatorRegistry the access validator registry
     * @return the AccessValidationService
     */
    @Bean
    @ConditionalOnMissingBean
    public AccessValidationService accessValidationService(AccessValidatorRegistry accessValidatorRegistry) {
        return new AccessValidationService(accessValidatorRegistry);
    }

    /**
     * Creates the AccessControlAspect bean if it doesn't exist.
     *
     * @param accessValidationService the AccessValidationService
     * @return the AccessControlAspect
     */
    @Bean
    @ConditionalOnMissingBean
    public AccessControlAspect accessControlAspect(AccessValidationService accessValidationService) {
        return new AccessControlAspect(accessValidationService);
    }
}
