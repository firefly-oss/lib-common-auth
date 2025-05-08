package com.catalis.common.auth.filter;

import com.catalis.common.auth.model.AuthDetails;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.springframework.web.server.WebFilterChain;

class AuthContextWebFilterTest {

    @Test
    void shouldCreateAuthenticationFromHeadersForCustomer() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "CUSTOMER")
                .header("X-Auth-Scopes", "contracts.read,accounts.write")
                .header("X-Request-ID", "req-123")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Check principal (partyId for CUSTOMER)
                    assertEquals("user123", auth.getName());

                    // Check authorities (roles and scopes)
                    List<String> authorities = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());

                    assertTrue(authorities.contains("ROLE_CUSTOMER"));
                    assertTrue(authorities.contains("SCOPE_contracts.read"));
                    assertTrue(authorities.contains("SCOPE_accounts.write"));

                    // Check details (requestId and employeeId)
                    assertTrue(auth.getDetails() instanceof AuthDetails);
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("req-123", details.getRequestId());
                    assertEquals("", details.getEmployeeId()); // Empty for CUSTOMER
                })
                .verifyComplete();
    }

    @Test
    void shouldCreateAuthenticationFromHeadersForEmployee() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Employee-ID", "emp123")
                .header("X-Auth-Roles", "ADMIN")
                .header("X-Auth-Scopes", "contracts.read,accounts.write")
                .header("X-Request-ID", "req-123")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Check principal (employeeId for employee roles)
                    assertEquals("emp123", auth.getName());

                    // Check authorities (roles and scopes)
                    List<String> authorities = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());

                    assertTrue(authorities.contains("ROLE_ADMIN"));
                    assertTrue(authorities.contains("SCOPE_contracts.read"));
                    assertTrue(authorities.contains("SCOPE_accounts.write"));

                    // Check details (requestId and employeeId)
                    assertTrue(auth.getDetails() instanceof AuthDetails);
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("req-123", details.getRequestId());
                    assertEquals("emp123", details.getEmployeeId());
                })
                .verifyComplete();
    }

    @Test
    void shouldReturnEmptyWhenAllIdHeadersAreMissing() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Auth-Roles", "CUSTOMER")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .verifyComplete();
    }

    @Test
    void shouldCreateAuthenticationWhenAnyIdHeaderIsProvided() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        // Test with only Party ID
        MockServerHttpRequest requestWithPartyId = MockServerHttpRequest.get("/test")
                .header("X-Party-ID", "user123")
                .header("X-Auth-Roles", "ADMIN") // Role doesn't match the ID type
                .build();

        MockServerWebExchange exchangeWithPartyId = MockServerWebExchange.from(requestWithPartyId);

        // Test with only Employee ID
        MockServerHttpRequest requestWithEmployeeId = MockServerHttpRequest.get("/test")
                .header("X-Employee-ID", "emp123")
                .header("X-Auth-Roles", "CUSTOMER") // Role doesn't match the ID type
                .build();

        MockServerWebExchange exchangeWithEmployeeId = MockServerWebExchange.from(requestWithEmployeeId);

        // Test with only Service Account ID
        MockServerHttpRequest requestWithServiceId = MockServerHttpRequest.get("/test")
                .header("X-Service-Account-ID", "service123")
                .header("X-Auth-Roles", "CUSTOMER") // Role doesn't match the ID type
                .build();

        MockServerWebExchange exchangeWithServiceId = MockServerWebExchange.from(requestWithServiceId);

        // When & Then - All should create authentication
        StepVerifier.create(filter.createAuthentication(exchangeWithPartyId))
                .assertNext(auth -> {
                    assertNotNull(auth);
                    assertEquals("user123", auth.getName());
                })
                .verifyComplete();

        StepVerifier.create(filter.createAuthentication(exchangeWithEmployeeId))
                .assertNext(auth -> {
                    assertNotNull(auth);
                    assertEquals("emp123", auth.getName());
                })
                .verifyComplete();

        StepVerifier.create(filter.createAuthentication(exchangeWithServiceId))
                .assertNext(auth -> {
                    assertNotNull(auth);
                    assertEquals("service123", auth.getName());
                })
                .verifyComplete();
    }

    @Test
    void shouldHandleEmptyRolesAndScopesForCustomer() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Party-ID", "user123")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Check principal (partyId for CUSTOMER)
                    assertEquals("user123", auth.getName());

                    // Check authorities (should be empty)
                    assertTrue(auth.getAuthorities().isEmpty());

                    // Check details (requestId and employeeId should be empty)
                    assertTrue(auth.getDetails() instanceof AuthDetails);
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("", details.getRequestId());
                    assertEquals("", details.getEmployeeId());
                })
                .verifyComplete();
    }

    @Test
    void shouldHandleEmptyRolesAndScopesForEmployee() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Employee-ID", "emp123")
                .header("X-Auth-Roles", "ADMIN")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Check principal (employeeId for employee roles)
                    assertEquals("emp123", auth.getName());

                    // Check authorities (should contain ROLE_ADMIN)
                    List<String> authorities = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());
                    assertTrue(authorities.contains("ROLE_ADMIN"));

                    // Check details (requestId should be empty, employeeId should be set)
                    assertTrue(auth.getDetails() instanceof AuthDetails);
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("", details.getRequestId());
                    assertEquals("emp123", details.getEmployeeId());
                })
                .verifyComplete();
    }
    @Test
    void shouldCreateAuthenticationFromHeadersForServiceAccount() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Service-Account-ID", "service123")
                .header("X-Auth-Roles", "SERVICE_ACCOUNT")
                .header("X-Auth-Scopes", "contracts.read,accounts.write")
                .header("X-Request-ID", "req-123")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Check principal (serviceAccountId for SERVICE_ACCOUNT)
                    assertEquals("service123", auth.getName());

                    // Check authorities (roles and scopes)
                    List<String> authorities = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());

                    assertTrue(authorities.contains("ROLE_SERVICE_ACCOUNT"));
                    assertTrue(authorities.contains("SCOPE_contracts.read"));
                    assertTrue(authorities.contains("SCOPE_accounts.write"));

                    // Check details (requestId, employeeId, and serviceAccountId)
                    assertTrue(auth.getDetails() instanceof AuthDetails);
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("req-123", details.getRequestId());
                    assertEquals("", details.getEmployeeId()); // Empty for SERVICE_ACCOUNT
                    assertEquals("service123", details.getServiceAccountId());
                })
                .verifyComplete();
    }

    @Test
    void shouldCreateAuthenticationWithMultipleIdHeaders() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        // Test with multiple ID headers
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Party-ID", "user123")
                .header("X-Employee-ID", "emp123")
                .header("X-Service-Account-ID", "service123")
                .header("X-Auth-Roles", "CUSTOMER,ADMIN,SERVICE_ACCOUNT")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then - Should use the principal based on role priority (service account > employee > customer)
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Principal should be set based on role priority
                    assertEquals("service123", auth.getName());

                    // All roles should be included
                    List<String> authorities = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());
                    assertTrue(authorities.contains("ROLE_CUSTOMER"));
                    assertTrue(authorities.contains("ROLE_ADMIN"));
                    assertTrue(authorities.contains("ROLE_SERVICE_ACCOUNT"));

                    // All IDs should be in the details
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("emp123", details.getEmployeeId());
                    assertEquals("service123", details.getServiceAccountId());
                })
                .verifyComplete();
    }

    @Test
    void shouldHandleEmptyRolesAndScopesForServiceAccount() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Service-Account-ID", "service123")
                .header("X-Auth-Roles", "SERVICE_ACCOUNT")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
                .assertNext(auth -> {
                    assertNotNull(auth);

                    // Check principal (serviceAccountId for SERVICE_ACCOUNT)
                    assertEquals("service123", auth.getName());

                    // Check authorities (should contain ROLE_SERVICE_ACCOUNT)
                    List<String> authorities = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());
                    assertTrue(authorities.contains("ROLE_SERVICE_ACCOUNT"));

                    // Check details (requestId should be empty, serviceAccountId should be set)
                    assertTrue(auth.getDetails() instanceof AuthDetails);
                    AuthDetails details = (AuthDetails) auth.getDetails();
                    assertEquals("", details.getRequestId());
                    assertEquals("", details.getEmployeeId());
                    assertEquals("service123", details.getServiceAccountId());
                })
                .verifyComplete();
    }

    @Test
    void shouldFilterExcludedPathsWithoutRequiredHeaders() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();
        WebFilterChain chain = mock(WebFilterChain.class);

        when(chain.filter(any())).thenReturn(Mono.empty());

        // Test with swagger-ui path
        MockServerHttpRequest request = MockServerHttpRequest.get("/swagger-ui")
                .header("X-Auth-Roles", "CUSTOMER") // Only role, no party ID
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        filter.filter(exchange, chain).block();

        // Then - should call the filter chain at least once
        // Note: We're using any() instead of the exact exchange object because
        // the filter now decorates the exchange with a response decorator
        verify(chain, atLeastOnce()).filter(any());
    }
}
