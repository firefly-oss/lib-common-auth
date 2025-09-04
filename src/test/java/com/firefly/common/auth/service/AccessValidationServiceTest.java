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


package com.firefly.common.auth.service;

import com.firefly.common.auth.model.AuthInfo;
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
        Mono<Boolean> result = accessValidationService.validateAccess("contract-example", "contract123", authInfo);

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
        Mono<Boolean> result = accessValidationService.validateAccess("contract-example", "contract123", authInfo);

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

        when(validatorRegistry.getValidator(eq("contract-example"))).thenReturn(validator);
        when(validator.canAccess(eq("contract123"), eq(authInfo))).thenReturn(Mono.just(true));

        // When
        Mono<Boolean> result = accessValidationService.validateAccess("contract-example", "contract123", authInfo);

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

        when(validatorRegistry.getValidator(eq("contract-example"))).thenReturn(validator);
        when(validator.canAccess(eq("contract123"), eq(authInfo))).thenReturn(Mono.just(false));

        // When
        Mono<Boolean> result = accessValidationService.validateAccess("contract-example", "contract123", authInfo);

        // Then
        StepVerifier.create(result)
                .expectNext(false)
                .verifyComplete();
    }
}
