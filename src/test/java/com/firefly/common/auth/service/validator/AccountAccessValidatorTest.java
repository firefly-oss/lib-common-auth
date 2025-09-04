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


package com.firefly.common.auth.service.validator;

import com.firefly.common.auth.model.AuthInfo;
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
        org.junit.jupiter.api.Assertions.assertEquals("account-example", resourceName);
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
