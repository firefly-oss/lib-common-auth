package com.firefly.common.auth.service.validator;

import com.firefly.common.auth.model.AuthInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Set;

class ContractAccessValidatorTest {

    private ContractAccessValidator validator;

    @BeforeEach
    void setUp() {
        validator = new ContractAccessValidator();
    }

    @Test
    void shouldReturnContractAsResourceName() {
        // When
        String resourceName = validator.getResourceName();

        // Then
        org.junit.jupiter.api.Assertions.assertEquals("contract-example", resourceName);
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
        Mono<Boolean> result = validator.canAccess("contract123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void shouldAllowAccessWhenUserIsOwner() {
        // Given
        String contractId = "contract123";
        AuthInfo authInfo = AuthInfo.builder()
                .partyId(contractId) // Same as contractId, so user is owner
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        Mono<Boolean> result = validator.canAccess(contractId, authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void shouldDenyAccessWhenUserIsNotOwner() {
        // Given
        String contractId = "contract123";
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123") // Different from contractId, so user is not owner
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        Mono<Boolean> result = validator.canAccess(contractId, authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }
}
