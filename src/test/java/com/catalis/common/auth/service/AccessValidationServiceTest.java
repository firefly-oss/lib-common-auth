package com.catalis.common.auth.service;

import com.catalis.common.auth.model.AuthInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessValidationServiceTest {

    @Mock
    private AccessValidatorRegistry validatorRegistry;

    @Mock
    private AccessValidator validator;

    private AccessValidationService accessValidationService;

    @BeforeEach
    void setUp() {
        accessValidationService = new AccessValidationService(validatorRegistry);
    }

    @Test
    void shouldAllowAccessWhenUserHasEmployeeRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Collections.emptySet())
                .build();

        // When
        Mono<Boolean> result = accessValidationService.validateAccess("contract", "contract123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void shouldThrowExceptionWhenValidatorNotFound() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        when(validatorRegistry.getValidator(anyString())).thenReturn(null);

        // When
        Mono<Boolean> result = accessValidationService.validateAccess("contract", "contract123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();
    }

    @Test
    void shouldReturnTrueWhenValidatorReturnsTrue() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        when(validatorRegistry.getValidator(eq("contract"))).thenReturn(validator);
        when(validator.canAccess(eq("contract123"), eq(authInfo))).thenReturn(Mono.just(true));

        // When
        Mono<Boolean> result = accessValidationService.validateAccess("contract", "contract123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void shouldReturnFalseWhenValidatorReturnsFalse() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        when(validatorRegistry.getValidator(eq("contract"))).thenReturn(validator);
        when(validator.canAccess(eq("contract123"), eq(authInfo))).thenReturn(Mono.just(false));

        // When
        Mono<Boolean> result = accessValidationService.validateAccess("contract", "contract123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }
}
