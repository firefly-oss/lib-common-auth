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
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.core.annotation.Order;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.reactivestreams.Publisher;

/**
 * WebFilter that reads headers injected by Istio/API Gateway and builds an Authentication object.
 * The headers include:
 * - X-Party-ID: identifier of the client (required for CUSTOMER role)
 * - X-Employee-ID: identifier of the employee (required for employee roles: ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF)
 * - X-Service-Account-ID: identifier of the service account (required for SERVICE_ACCOUNT role)
 * - X-Auth-Roles: roles of the subject (CUSTOMER, ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF, SERVICE_ACCOUNT), comma-separated
 * - X-Auth-Scopes: OAuth2 scopes like contracts.read, accounts.write, comma-separated
 * - X-Request-ID: for traceability
 */
@Component
@Order(1) // High priority to ensure it's executed before other filters
@Slf4j
public class AuthContextWebFilter implements WebFilter {

    private static final String PARTY_ID_HEADER = "X-Party-ID";
    private static final String EMPLOYEE_ID_HEADER = "X-Employee-ID";
    private static final String SERVICE_ACCOUNT_ID_HEADER = "X-Service-Account-ID";
    private static final String ROLES_HEADER = "X-Auth-Roles";
    private static final String SCOPES_HEADER = "X-Auth-Scopes";
    private static final String REQUEST_ID_HEADER = "X-Request-ID";

    // Paths that should be excluded from header validation
    private static final List<String> EXCLUDED_PATHS = Arrays.asList(
            "/swagger-ui", 
            "/v3/api-docs", 
            "/actuator", 
            "/webjars/swagger-ui",
            "/swagger-resources");

    /**
     * Checks if the current request path should be excluded from header validation.
     * 
     * @param exchange the server web exchange
     * @return true if the path should be excluded, false otherwise
     */
    private boolean isExcludedPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getURI().getPath();
        return EXCLUDED_PATHS.stream().anyMatch(path::startsWith);
    }

    /**
     * Creates an Authentication object from the headers in the exchange.
     * This method is used by the filter and can also be used directly by tests.
     *
     * @param exchange the server web exchange
     * @return a Mono that emits the Authentication object, or empty if required headers are missing
     */
    public Mono<Authentication> createAuthentication(ServerWebExchange exchange) {
        // This method is only called for non-excluded paths as excluded paths are handled directly in the filter method

        // Extract headers
        String partyId = exchange.getRequest().getHeaders().getFirst(PARTY_ID_HEADER);
        String employeeId = exchange.getRequest().getHeaders().getFirst(EMPLOYEE_ID_HEADER);
        String serviceAccountId = exchange.getRequest().getHeaders().getFirst(SERVICE_ACCOUNT_ID_HEADER);
        String roles = exchange.getRequest().getHeaders().getFirst(ROLES_HEADER);
        String scopes = exchange.getRequest().getHeaders().getFirst(SCOPES_HEADER);
        String requestId = exchange.getRequest().getHeaders().getFirst(REQUEST_ID_HEADER);

        // Log headers for debugging
        log.info("Headers: partyId={}, employeeId={}, serviceAccountId={}, roles={}, scopes={}, requestId={}", 
                 partyId, employeeId, serviceAccountId, roles, scopes, requestId);

        // Parse roles to determine user type
        boolean isEmployee = false;
        boolean isServiceAccount = false;
        if (roles != null && !roles.isEmpty()) {
            String[] roleArray = roles.split(",");
            isEmployee = Arrays.stream(roleArray)
                    .map(String::trim)
                    .anyMatch(role -> role.equals("ADMIN") || 
                                      role.equals("CUSTOMER_SUPPORT") || 
                                      role.equals("SUPERVISOR") || 
                                      role.equals("MANAGER") || 
                                      role.equals("BRANCH_STAFF"));
            isServiceAccount = Arrays.stream(roleArray)
                    .map(String::trim)
                    .anyMatch(role -> role.equals("SERVICE_ACCOUNT"));
        }

        // Validate headers - require at least one ID header
        if ((partyId == null || partyId.isEmpty()) && 
            (employeeId == null || employeeId.isEmpty()) && 
            (serviceAccountId == null || serviceAccountId.isEmpty())) {
            log.warn("Missing required ID header. At least one of {}, {}, or {} must be provided", 
                    PARTY_ID_HEADER, EMPLOYEE_ID_HEADER, SERVICE_ACCOUNT_ID_HEADER);
            return Mono.empty();
        }

        // Build authorities list from roles and scopes
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // Add roles as authorities with ROLE_ prefix
        if (roles != null && !roles.isEmpty()) {
            authorities.addAll(
                    Arrays.stream(roles.split(","))
                            .map(String::trim)
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toList())
            );
        }

        // Add scopes as authorities with SCOPE_ prefix
        if (scopes != null && !scopes.isEmpty()) {
            authorities.addAll(
                    Arrays.stream(scopes.split(","))
                            .map(String::trim)
                            .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                            .collect(Collectors.toList())
            );
        }

        // Create authentication details with request ID, employee ID, and service account ID
        AuthDetails authDetails = AuthDetails.builder()
                .requestId(requestId != null ? requestId : "")
                .employeeId(employeeId != null ? employeeId : "")
                .serviceAccountId(serviceAccountId != null ? serviceAccountId : "")
                .build();

        // Create authentication object with appropriate principal based on available ID headers
        // Priority order: service account ID > employee ID > party ID
        String principal;
        if (serviceAccountId != null && !serviceAccountId.isEmpty()) {
            principal = serviceAccountId;
        } else if (employeeId != null && !employeeId.isEmpty()) {
            principal = employeeId;
        } else {
            principal = partyId;
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                principal, // principal (username)
                null,      // credentials (not used)
                authorities
        );

        // Set authentication details
        ((UsernamePasswordAuthenticationToken) authentication).setDetails(authDetails);

        return Mono.just(authentication);
    }

    /**
     * Process the request through the filter chain with a decorated response.
     * This allows us to properly handle the response before returning it.
     *
     * @param exchange the server web exchange
     * @param chain the web filter chain
     * @param authentication the authentication object
     * @return a Mono that completes when the response has been written
     */
    private Mono<Void> processThroughFilterChain(ServerWebExchange exchange, WebFilterChain chain, Authentication authentication) {
        log.info("AuthContextWebFilter.processThroughFilterChain: Processing request through filter chain");
        ServerHttpResponse originalResponse = exchange.getResponse();
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                log.info("AuthContextWebFilter.writeWith: Writing response");
                // Convert the body to a Flux regardless of its type
                Flux<DataBuffer> fluxBody = Flux.from(body);

                return super.writeWith(fluxBody.collectList().map(dataBuffers -> {
                    log.info("AuthContextWebFilter.writeWith: Collected response body");
                    // Combine all DataBuffers to get the complete response body
                    DataBuffer joinedBuffer = exchange.getResponse().bufferFactory().join(dataBuffers);

                    // Create a copy of the buffer for writing to the response
                    byte[] content = new byte[joinedBuffer.readableByteCount()];
                    joinedBuffer.read(content);
                    DataBuffer copiedBuffer = exchange.getResponse().bufferFactory().wrap(content);

                    return copiedBuffer;
                }).flux());
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build())
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
                .doOnSuccess(v -> log.info("AuthContextWebFilter.processThroughFilterChain: Successfully processed request through filter chain"))
                .doOnError(e -> log.error("AuthContextWebFilter.processThroughFilterChain: Error processing request through filter chain: {}", e.getMessage(), e));
    }

    /**
     * Process the request through the filter chain with a decorated response for excluded paths.
     * This allows us to properly handle the response before returning it, without adding authentication.
     *
     * @param exchange the server web exchange
     * @param chain the web filter chain
     * @return a Mono that completes when the response has been written
     */
    private Mono<Void> processExcludedPathThroughFilterChain(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("AuthContextWebFilter.processExcludedPathThroughFilterChain: Processing excluded path request through filter chain");
        ServerHttpResponse originalResponse = exchange.getResponse();
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                log.info("AuthContextWebFilter.writeWith: Writing response for excluded path");
                // Convert the body to a Flux regardless of its type
                Flux<DataBuffer> fluxBody = Flux.from(body);

                return super.writeWith(fluxBody.collectList().map(dataBuffers -> {
                    log.info("AuthContextWebFilter.writeWith: Collected response body for excluded path");
                    // Combine all DataBuffers to get the complete response body
                    DataBuffer joinedBuffer = exchange.getResponse().bufferFactory().join(dataBuffers);

                    // Create a copy of the buffer for writing to the response
                    byte[] content = new byte[joinedBuffer.readableByteCount()];
                    joinedBuffer.read(content);
                    DataBuffer copiedBuffer = exchange.getResponse().bufferFactory().wrap(content);

                    return copiedBuffer;
                }).flux());
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build())
                .doOnSuccess(v -> log.info("AuthContextWebFilter.processExcludedPathThroughFilterChain: Successfully processed excluded path request through filter chain"))
                .doOnError(e -> log.error("AuthContextWebFilter.processExcludedPathThroughFilterChain: Error processing excluded path request through filter chain: {}", e.getMessage(), e));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        
        if (isExcludedPath(exchange)) {
            log.info("Bypassing authentication for excluded path: {}", path);
            return processExcludedPathThroughFilterChain(exchange, chain);
        }

        // For non-excluded paths, create appropriate authentication
        return createAuthentication(exchange)
                .flatMap(authentication -> processThroughFilterChain(exchange, chain, authentication))
                .switchIfEmpty(chain.filter(exchange));
    }
}
