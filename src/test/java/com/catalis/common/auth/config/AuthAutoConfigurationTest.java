package com.catalis.common.auth.config;

import com.catalis.common.auth.aspect.AccessControlAspect;
import com.catalis.common.auth.filter.AuthContextWebFilter;
import com.catalis.common.auth.service.AccessValidationService;
import com.catalis.common.auth.service.AccessValidatorRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

class AuthAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthAutoConfiguration.class));

    @Test
    void shouldCreateDefaultBeans() {
        contextRunner.run(context -> {
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
                .withUserConfiguration(CustomConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthContextWebFilter.class);
                    assertThat(context).hasSingleBean(AccessValidatorRegistry.class);
                    assertThat(context).hasSingleBean(AccessValidationService.class);
                    assertThat(context).hasSingleBean(AccessControlAspect.class);

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
    static class CustomConfiguration {

        @Bean
        public AuthContextWebFilter authContextWebFilter() {
            return new CustomAuthContextWebFilter();
        }

        @Bean
        public AccessValidatorRegistry accessValidatorRegistry() {
            return new CustomAccessValidatorRegistry();
        }

        @Bean
        public AccessValidationService accessValidationService() {
            return new CustomAccessValidationService();
        }

        @Bean
        public AccessControlAspect accessControlAspect() {
            return new CustomAccessControlAspect();
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
