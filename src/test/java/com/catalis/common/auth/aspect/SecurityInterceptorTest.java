package com.catalis.common.auth.aspect;

import com.catalis.common.auth.annotation.*;
import com.catalis.common.auth.model.AuthDetails;
import com.catalis.common.auth.model.AuthInfo;
import com.catalis.common.auth.service.AccessValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityInterceptorTest {

    @Mock
    private AccessValidationService accessValidationService;

    private SecurityInterceptor interceptor;
    private TestService testService;
    private TestService proxiedService;

    @BeforeEach
    void setUp() {
        interceptor = new SecurityInterceptor(accessValidationService);

        // Create the test service
        testService = new TestService();

        // Create a proxy factory
        AspectJProxyFactory factory = new AspectJProxyFactory(testService);

        // Add the interceptor
        factory.addAspect(interceptor);

        // Create the proxy
        proxiedService = factory.getProxy();
    }

    @Test
    void shouldAllowAccessWhenUserHasRequiredRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Collections.emptySet())
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.adminMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("Admin method")
                .verifyComplete();
    }

    @Test
    void shouldDenyAccessWhenUserDoesNotHaveRequiredRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.adminMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();
    }

    @Test
    void shouldAllowAccessWhenUserHasRequiredScope() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Set.of("contracts.read"))
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(
                        new SimpleGrantedAuthority("ROLE_CUSTOMER"),
                        new SimpleGrantedAuthority("SCOPE_contracts.read")
                )
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.readContractMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("Read contract method")
                .verifyComplete();
    }

    @Test
    void shouldDenyAccessWhenUserDoesNotHaveRequiredScope() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Set.of("accounts.read"))
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(
                        new SimpleGrantedAuthority("ROLE_CUSTOMER"),
                        new SimpleGrantedAuthority("SCOPE_accounts.read")
                )
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.readContractMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();
    }

    @Test
    void shouldAllowAccessWhenUserIsOwnerOfResource() {
        // Given
        String contractId = "contract123";
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // Mock the validation service
        when(accessValidationService.validateAccess(eq("contract-example"), eq(contractId), any(AuthInfo.class)))
                .thenReturn(Mono.just(true));

        // When
        Mono<String> result = proxiedService.getContractById(contractId)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("Contract: " + contractId)
                .verifyComplete();

        verify(accessValidationService).validateAccess(eq("contract-example"), eq(contractId), any(AuthInfo.class));
    }

    @Test
    void shouldDenyAccessWhenUserIsNotOwnerOfResource() {
        // Given
        String contractId = "contract123";
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // Mock the validation service
        when(accessValidationService.validateAccess(eq("contract-example"), eq(contractId), any(AuthInfo.class)))
                .thenReturn(Mono.just(false));

        // When
        Mono<String> result = proxiedService.getContractById(contractId)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();

        verify(accessValidationService).validateAccess(eq("contract-example"), eq(contractId), any(AuthInfo.class));
    }

    @Test
    void shouldAllowAccessWhenExpressionEvaluatesToTrue() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Collections.emptySet())
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.expressionMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("Expression method")
                .verifyComplete();
    }

    @Test
    void shouldDenyAccessWhenExpressionEvaluatesToFalse() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(new SimpleGrantedAuthority("ROLE_CUSTOMER"))
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.expressionMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();
    }

    @Test
    void shouldAllowAccessWhenPreAuthorizeExpressionEvaluatesToTrue() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Set.of("contracts.write"))
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("SCOPE_contracts.write")
                )
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.preAuthorizeMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("PreAuthorize method")
                .verifyComplete();
    }

    @Test
    void shouldDenyAccessWhenPreAuthorizeExpressionEvaluatesToFalse() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Set.of("accounts.write"))
                .requestId("req-123")
                .build();

        // Mock the authentication
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authInfo.getPartyId(),
                null,
                Arrays.asList(
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("SCOPE_accounts.write")
                )
        );
        AuthDetails details = AuthDetails.builder().requestId(authInfo.getRequestId()).build();
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);

        // When
        Mono<String> result = proxiedService.preAuthorizeMethod()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();
    }

    // Test service with methods annotated with security annotations
    static class TestService {

        @RequiresRole("ADMIN")
        public Mono<String> adminMethod() {
            return Mono.just("Admin method");
        }

        @RequiresScope("contracts.read")
        public Mono<String> readContractMethod() {
            return Mono.just("Read contract method");
        }

        @RequiresOwnership(resource = "contract-example", paramName = "contractId")
        public Mono<String> getContractById(String contractId) {
            return Mono.just("Contract: " + contractId);
        }

        @RequiresExpression("#authInfo.isEmployee()")
        public Mono<String> expressionMethod() {
            return Mono.just("Expression method");
        }

        @PreAuthorize("#authInfo.hasRole('ADMIN') && #authInfo.hasScope('contracts.write')")
        public Mono<String> preAuthorizeMethod() {
            return Mono.just("PreAuthorize method");
        }
    }
}
