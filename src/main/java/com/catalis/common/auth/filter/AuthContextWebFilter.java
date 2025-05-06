package com.catalis.common.auth.filter;

import com.catalis.common.auth.model.AuthDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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
@Slf4j
public class AuthContextWebFilter implements WebFilter {

    private static final String PARTY_ID_HEADER = "X-Party-ID";
    private static final String EMPLOYEE_ID_HEADER = "X-Employee-ID";
    private static final String SERVICE_ACCOUNT_ID_HEADER = "X-Service-Account-ID";
    private static final String ROLES_HEADER = "X-Auth-Roles";
    private static final String SCOPES_HEADER = "X-Auth-Scopes";
    private static final String REQUEST_ID_HEADER = "X-Request-ID";

    /**
     * Creates an Authentication object from the headers in the exchange.
     * This method is used by the filter and can also be used directly by tests.
     *
     * @param exchange the server web exchange
     * @return a Mono that emits the Authentication object, or empty if required headers are missing
     */
    public Mono<Authentication> createAuthentication(ServerWebExchange exchange) {
        // Extract headers
        String partyId = exchange.getRequest().getHeaders().getFirst(PARTY_ID_HEADER);
        String employeeId = exchange.getRequest().getHeaders().getFirst(EMPLOYEE_ID_HEADER);
        String serviceAccountId = exchange.getRequest().getHeaders().getFirst(SERVICE_ACCOUNT_ID_HEADER);
        String roles = exchange.getRequest().getHeaders().getFirst(ROLES_HEADER);
        String scopes = exchange.getRequest().getHeaders().getFirst(SCOPES_HEADER);
        String requestId = exchange.getRequest().getHeaders().getFirst(REQUEST_ID_HEADER);

        // Log headers for debugging
        log.debug("Headers: partyId={}, employeeId={}, serviceAccountId={}, roles={}, scopes={}, requestId={}", 
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

        // Validate headers based on user type
        if (isServiceAccount) {
            // For SERVICE_ACCOUNT users, X-Service-Account-ID is required
            if (serviceAccountId == null || serviceAccountId.isEmpty()) {
                log.warn("Missing required header for SERVICE_ACCOUNT user: {}", SERVICE_ACCOUNT_ID_HEADER);
                return Mono.empty();
            }
        } else if (isEmployee) {
            // For employee users, X-Employee-ID is required
            if (employeeId == null || employeeId.isEmpty()) {
                log.warn("Missing required header for employee user: {}", EMPLOYEE_ID_HEADER);
                return Mono.empty();
            }
        } else {
            // For CUSTOMER users, X-Party-ID is required
            if (partyId == null || partyId.isEmpty()) {
                log.warn("Missing required header for CUSTOMER user: {}", PARTY_ID_HEADER);
                return Mono.empty();
            }
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

        // Create authentication object with appropriate principal based on user type
        String principal;
        if (isServiceAccount) {
            principal = serviceAccountId;
        } else if (isEmployee) {
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

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return createAuthentication(exchange)
                .flatMap(authentication -> 
                    chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
                )
                .switchIfEmpty(chain.filter(exchange));
    }
}
