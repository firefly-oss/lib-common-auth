package com.catalis.common.auth.service.validator;

import com.catalis.common.auth.model.AuthInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.Set;

class AccountAccessValidatorTest {

    private AccountAccessValidator validator;

    @BeforeEach
    void setUp() {
        validator = new AccountAccessValidator();
    }

    @Test
    void shouldReturnAccountAsResourceName() {
        // When
        String resourceName = validator.getResourceName();

        // Then
        org.junit.jupiter.api.Assertions.assertEquals("account", resourceName);
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
        Mono<Boolean> result = validator.canAccess("account123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void shouldAllowAccessWhenUserIsOwner() {
        // Given
        String accountId = "account123";
        AuthInfo authInfo = AuthInfo.builder()
                .partyId(accountId) // Same as accountId, so user is owner
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        Mono<Boolean> result = validator.canAccess(accountId, authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void shouldDenyAccessWhenUserIsNotOwner() {
        // Given
        String accountId = "account123";
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123") // Different from accountId, so user is not owner
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        Mono<Boolean> result = validator.canAccess(accountId, authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }
}
