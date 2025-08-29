package com.firefly.common.auth.config.openapi;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.OpenAPI;
import org.springdoc.core.customizers.OpenApiCustomizer;

/**
 * Configuration class for OpenAPI customization.
 * This class provides the necessary beans for customizing OpenAPI documentation
 * with authentication headers.
 * 
 * It's designed to work alongside lib-common-web's OpenAPI bean, providing
 * auth headers customization without conflicting with the other library.
 */
@Configuration
public class OpenAPIConfiguration {

    /**
     * Creates the AuthHeadersOpenAPICustomizer bean if it doesn't exist.
     * This bean adds authentication headers to all operations in the OpenAPI documentation.
     *
     * @return the AuthHeadersOpenAPICustomizer
     */
    @Bean
    public AuthHeadersOpenAPICustomizer authHeadersOpenAPICustomizer() {
        return new AuthHeadersOpenAPICustomizer();
    }
}
