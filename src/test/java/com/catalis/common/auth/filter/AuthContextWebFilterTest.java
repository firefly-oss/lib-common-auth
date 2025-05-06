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
    void shouldReturnEmptyWhenPartyIdIsMissingForCustomer() {
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
    void shouldReturnEmptyWhenEmployeeIdIsMissingForEmployee() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Auth-Roles", "ADMIN")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
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
    void shouldReturnEmptyWhenServiceAccountIdIsMissingForServiceAccount() {
        // Given
        AuthContextWebFilter filter = new AuthContextWebFilter();

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("X-Auth-Roles", "SERVICE_ACCOUNT")
                .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // When
        Mono<Authentication> authMono = filter.createAuthentication(exchange);

        // Then
        StepVerifier.create(authMono)
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
}
