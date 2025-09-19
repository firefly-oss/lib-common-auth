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


package com.firefly.common.auth.filter;

import com.firefly.common.auth.model.AuthDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for metadata functionality in AuthContextWebFilter.
 */
class AuthContextWebFilterMetadataTest {

    private AuthContextWebFilter filter;

    @BeforeEach
    void setUp() {
        filter = new AuthContextWebFilter();
    }

    @Test
    void shouldExtractStringMetadata() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Department", "IT")
                .header("X-Auth-Metadata-Branch", "Main")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    assertNotNull(authentication);
                    assertTrue(authentication.getDetails() instanceof AuthDetails);
                    
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(2, metadata.size());
                    assertEquals("IT", metadata.get("Department"));
                    assertEquals("Main", metadata.get("Branch"));
                })
                .verifyComplete();
    }

    @Test
    void shouldExtractAndParseIntegerMetadata() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Level", "5")
                .header("X-Auth-Metadata-Priority", "100")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(2, metadata.size());
                    assertEquals(5, metadata.get("Level"));
                    assertEquals(100, metadata.get("Priority"));
                    assertTrue(metadata.get("Level") instanceof Integer);
                    assertTrue(metadata.get("Priority") instanceof Integer);
                })
                .verifyComplete();
    }

    @Test
    void shouldExtractAndParseBooleanMetadata() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Active", "true")
                .header("X-Auth-Metadata-Verified", "false")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(2, metadata.size());
                    assertEquals(true, metadata.get("Active"));
                    assertEquals(false, metadata.get("Verified"));
                    assertTrue(metadata.get("Active") instanceof Boolean);
                    assertTrue(metadata.get("Verified") instanceof Boolean);
                })
                .verifyComplete();
    }

    @Test
    void shouldExtractAndParseDoubleMetadata() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Score", "95.5")
                .header("X-Auth-Metadata-Rate", "0.15")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(2, metadata.size());
                    assertEquals(95.5, metadata.get("Score"));
                    assertEquals(0.15, metadata.get("Rate"));
                    assertTrue(metadata.get("Score") instanceof Double);
                    assertTrue(metadata.get("Rate") instanceof Double);
                })
                .verifyComplete();
    }

    @Test
    void shouldExtractMixedTypeMetadata() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Department", "IT")
                .header("X-Auth-Metadata-Level", "5")
                .header("X-Auth-Metadata-Active", "true")
                .header("X-Auth-Metadata-Score", "95.5")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(4, metadata.size());
                    assertEquals("IT", metadata.get("Department"));
                    assertEquals(5, metadata.get("Level"));
                    assertEquals(true, metadata.get("Active"));
                    assertEquals(95.5, metadata.get("Score"));
                    
                    assertTrue(metadata.get("Department") instanceof String);
                    assertTrue(metadata.get("Level") instanceof Integer);
                    assertTrue(metadata.get("Active") instanceof Boolean);
                    assertTrue(metadata.get("Score") instanceof Double);
                })
                .verifyComplete();
    }

    @Test
    void shouldHandleEmptyMetadata() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertTrue(metadata.isEmpty());
                })
                .verifyComplete();
    }

    @Test
    void shouldIgnoreNonMetadataHeaders() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Department", "IT")
                .header("X-Custom-Header", "should-be-ignored")
                .header("Authorization", "Bearer token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(1, metadata.size());
                    assertEquals("IT", metadata.get("Department"));
                    assertFalse(metadata.containsKey("Custom-Header"));
                    assertFalse(metadata.containsKey("Authorization"));
                })
                .verifyComplete();
    }

    @Test
    void shouldHandleEmptyMetadataValues() {
        // Given
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Metadata-Department", "")
                .header("X-Auth-Metadata-Branch", "   ")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> result = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(result)
                .assertNext(authentication -> {
                    AuthDetails details = (AuthDetails) authentication.getDetails();
                    Map<String, Object> metadata = details.getMetadata();
                    
                    assertEquals(2, metadata.size());
                    assertEquals("", metadata.get("Department"));
                    assertEquals("   ", metadata.get("Branch"));
                })
                .verifyComplete();
    }
}
