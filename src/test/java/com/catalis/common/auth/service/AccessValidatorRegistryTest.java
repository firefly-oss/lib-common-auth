package com.catalis.common.auth.service;

import com.catalis.common.auth.annotation.AccessValidatorFor;
import com.catalis.common.auth.model.AuthInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessValidatorRegistryTest {

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private AccessValidator contractValidator;

    @Mock
    private AccessValidator accountValidator;

    private AccessValidatorRegistry registry;

    @BeforeEach
    void setUp() {
        // Create mock validators
        when(contractValidator.getResourceName()).thenReturn("contract-example");
        when(accountValidator.getResourceName()).thenReturn("account-example");

        // Create a map of validators
        Map<String, AccessValidator> validators = new HashMap<>();
        validators.put("contractValidator", contractValidator);
        validators.put("accountValidator", accountValidator);

        // Mock the ApplicationContext to return the validators
        when(applicationContext.getBeansOfType(AccessValidator.class)).thenReturn(validators);

        // Create the registry
        registry = new AccessValidatorRegistry(applicationContext);
        registry.init();
    }

    @Test
    void shouldRegisterValidatorsOnInit() {
        // Then
        assertTrue(registry.hasValidator("contract-example"));
        assertTrue(registry.hasValidator("account-example"));
        assertFalse(registry.hasValidator("nonexistent"));
    }

    @Test
    void shouldGetValidatorByResourceType() {
        // When
        AccessValidator validator = registry.getValidator("contract-example");

        // Then
        assertNotNull(validator);
        assertEquals(contractValidator, validator);
    }

    @Test
    void shouldReturnNullWhenValidatorNotFound() {
        // When
        AccessValidator validator = registry.getValidator("nonexistent");

        // Then
        assertNull(validator);
    }

    @Test
    void shouldGetResourceNameFromAnnotation() {
        // Given
        AccessValidator validatorWithAnnotation = new TestValidatorWithAnnotation();
        Map<String, AccessValidator> validators = new HashMap<>();
        validators.put("validatorWithAnnotation", validatorWithAnnotation);
        when(applicationContext.getBeansOfType(AccessValidator.class)).thenReturn(validators);

        // When
        AccessValidatorRegistry registry = new AccessValidatorRegistry(applicationContext);
        registry.init();

        // Then
        assertTrue(registry.hasValidator("test"));
        assertEquals(validatorWithAnnotation, registry.getValidator("test"));
    }

    @Test
    void shouldGetResourceNameFromMethod() {
        // Given
        AccessValidator validatorWithoutAnnotation = new TestValidatorWithoutAnnotation();
        Map<String, AccessValidator> validators = new HashMap<>();
        validators.put("validatorWithoutAnnotation", validatorWithoutAnnotation);
        when(applicationContext.getBeansOfType(AccessValidator.class)).thenReturn(validators);

        // When
        AccessValidatorRegistry registry = new AccessValidatorRegistry(applicationContext);
        registry.init();

        // Then
        assertTrue(registry.hasValidator("test-method"));
        assertEquals(validatorWithoutAnnotation, registry.getValidator("test-method"));
    }

    @AccessValidatorFor("test")
    static class TestValidatorWithAnnotation implements AccessValidator {
        @Override
        public String getResourceName() {
            return "fallback";
        }

        @Override
        public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
            return Mono.just(true);
        }
    }

    static class TestValidatorWithoutAnnotation implements AccessValidator {
        @Override
        public String getResourceName() {
            return "test-method";
        }

        @Override
        public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
            return Mono.just(true);
        }
    }
}
