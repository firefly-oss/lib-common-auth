package com.catalis.common.auth.aspect;

import com.catalis.common.auth.annotation.CheckAccess;
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
class AccessControlAspectTest {

    @Mock
    private AccessValidationService accessValidationService;

    private AccessControlAspect aspect;
    private TestService testService;
    private TestService proxiedService;

    @BeforeEach
    void setUp() {
        aspect = new AccessControlAspect(accessValidationService);

        // Create the test service
        testService = new TestService();

        // Create a proxy factory
        AspectJProxyFactory factory = new AspectJProxyFactory(testService);

        // Add the aspect
        factory.addAspect(aspect);

        // Create the proxy
        proxiedService = factory.getProxy();
    }

    @Test
    void shouldAllowAccessWhenValidationSucceeds() {
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
        when(accessValidationService.validateAccess(eq("contract"), eq(contractId), any(AuthInfo.class)))
                .thenReturn(Mono.just(true));

        // When
        Mono<String> result = proxiedService.getContractById(contractId)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("Contract: " + contractId)
                .verifyComplete();

        verify(accessValidationService).validateAccess(eq("contract"), eq(contractId), any(AuthInfo.class));
    }

    @Test
    void shouldDenyAccessWhenValidationFails() {
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
        when(accessValidationService.validateAccess(eq("contract"), eq(contractId), any(AuthInfo.class)))
                .thenReturn(Mono.just(false));

        // When
        Mono<String> result = proxiedService.getContractById(contractId)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectError(AccessDeniedException.class)
                .verify();

        verify(accessValidationService).validateAccess(eq("contract"), eq(contractId), any(AuthInfo.class));
    }

    @Test
    void shouldAllowAccessToAccountWhenValidationSucceeds() {
        // Given
        String accountId = "account123";
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

        // Mock the validation service
        when(accessValidationService.validateAccess(eq("account"), eq(accountId), any(AuthInfo.class)))
                .thenReturn(Mono.just(true));

        // When
        Mono<String> result = proxiedService.getAccountById(accountId)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        // Then
        StepVerifier.create(result)
                .expectNext("Account: " + accountId)
                .verifyComplete();

        verify(accessValidationService).validateAccess(eq("account"), eq(accountId), any(AuthInfo.class));
    }

    // Test service with methods annotated with @CheckAccess
    static class TestService {

        @CheckAccess(resource = "contract", idParam = "contractId")
        public Mono<String> getContractById(String contractId) {
            return Mono.just("Contract: " + contractId);
        }

        @CheckAccess(resource = "account", idParam = "accountId")
        public Mono<String> getAccountById(String accountId) {
            return Mono.just("Account: " + accountId);
        }
    }
}
