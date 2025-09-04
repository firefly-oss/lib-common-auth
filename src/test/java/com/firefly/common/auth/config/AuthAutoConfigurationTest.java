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


package com.firefly.common.auth.config;

import com.firefly.common.auth.aspect.AccessControlAspect;
import com.firefly.common.auth.filter.AuthContextWebFilter;
import com.firefly.common.auth.service.AccessValidationService;
import com.firefly.common.auth.service.AccessValidatorRegistry;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AuthAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner();

    @Test
    void shouldCreateDefaultBeans() {
        contextRunner
                .withConfiguration(AutoConfigurations.of(AuthAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthContextWebFilter.class);
                    assertThat(context).hasSingleBean(AccessValidatorRegistry.class);
                    assertThat(context).hasSingleBean(AccessValidationService.class);
                    assertThat(context).hasSingleBean(AccessControlAspect.class);
                    assertThat(context).hasSingleBean(SecurityWebFilterChain.class);
                });
    }

    @Test
    void shouldNotOverrideExistingBeans() {
        contextRunner
                .withUserConfiguration(TestConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthContextWebFilter.class);
                    assertThat(context).hasSingleBean(AccessValidatorRegistry.class);
                    assertThat(context).hasSingleBean(AccessValidationService.class);
                    assertThat(context).hasSingleBean(AccessControlAspect.class);
                    assertThat(context).hasSingleBean(SecurityWebFilterChain.class);

                    // Verify that our custom beans are used
                    assertThat(context.getBean(AuthContextWebFilter.class))
                            .isInstanceOf(CustomAuthContextWebFilter.class);
                    assertThat(context.getBean(AccessValidatorRegistry.class))
                            .isInstanceOf(CustomAccessValidatorRegistry.class);
                    assertThat(context.getBean(AccessValidationService.class))
                            .isInstanceOf(CustomAccessValidationService.class);
                    assertThat(context.getBean(AccessControlAspect.class))
                            .isInstanceOf(CustomAccessControlAspect.class);
                });
    }

    @Configuration
    static class TestConfig extends AuthAutoConfiguration {

        @Bean
        @Override
        public AuthContextWebFilter authContextWebFilter() {
            return new CustomAuthContextWebFilter();
        }

        @Bean
        @Override
        public AccessValidatorRegistry accessValidatorRegistry(org.springframework.context.ApplicationContext applicationContext) {
            return new CustomAccessValidatorRegistry();
        }

        @Bean
        @Override
        public AccessValidationService accessValidationService(AccessValidatorRegistry accessValidatorRegistry) {
            return new CustomAccessValidationService();
        }

        @Bean
        @Override
        public AccessControlAspect accessControlAspect(AccessValidationService accessValidationService) {
            return new CustomAccessControlAspect();
        }

        @Bean
        @Override
        public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
            return super.securityWebFilterChain(http);
        }
    }

    static class CustomAuthContextWebFilter extends AuthContextWebFilter {
    }

    static class CustomAccessValidatorRegistry extends AccessValidatorRegistry {
        public CustomAccessValidatorRegistry() {
            super(null);
        }

        @Override
        public void init() {
            // Do nothing to avoid NullPointerException
        }
    }

    static class CustomAccessValidationService extends AccessValidationService {
        public CustomAccessValidationService() {
            super(null);
        }
    }

    static class CustomAccessControlAspect extends AccessControlAspect {
        public CustomAccessControlAspect() {
            super(null);
        }
    }
}
