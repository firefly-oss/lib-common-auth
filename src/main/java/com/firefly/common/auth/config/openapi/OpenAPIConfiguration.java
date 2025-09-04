/*
 * Copyright 2025 Firefly Software Solutions Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


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
