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


package com.firefly.common.auth.model;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Wrapper utility class that provides access to authentication information.
 * This class exposes methods to access the party ID, employee ID, service account ID, roles, scopes, and metadata of the authenticated user.
 */
@Data
@Builder
@Slf4j
public class AuthInfo {

    private final String partyId;
    private final String employeeId;
    private final String serviceAccountId;
    private final Set<String> roles;
    private final Set<String> scopes;
    private final String requestId;

    /**
     * Additional metadata that can be used to store custom authentication information.
     * This map can contain any key-value pairs that provide additional context about the user.
     * Examples: department, branch, region, permissions, etc.
     */
    @Builder.Default
    private final Map<String, Object> metadata = Collections.emptyMap();

    /**
     * Gets the current AuthInfo from the ReactiveSecurityContextHolder.
     *
     * @return a Mono that emits the current AuthInfo
     */
    public static Mono<AuthInfo> getCurrent() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(authentication -> {
                    if (authentication == null) {
                        log.warn("No authentication found in security context");
                        return AuthInfo.builder()
                                .partyId("")
                                .roles(Collections.emptySet())
                                .scopes(Collections.emptySet())
                                .requestId("")
                                .metadata(Collections.emptyMap())
                                .build();
                    }

                    // Extract roles from authorities
                    Set<String> roles = authentication.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(authority -> authority.startsWith("ROLE_"))
                            .map(authority -> authority.substring(5)) // Remove "ROLE_" prefix
                            .collect(Collectors.toSet());

                    // Extract scopes from authorities
                    Set<String> scopes = authentication.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(authority -> authority.startsWith("SCOPE_"))
                            .map(authority -> authority.substring(6)) // Remove "SCOPE_" prefix
                            .collect(Collectors.toSet());

                    // Extract partyId from principal
                    String partyId = authentication.getName();

                    // Extract requestId, employeeId, serviceAccountId, and metadata from details if available
                    String requestId = "";
                    String employeeId = "";
                    String serviceAccountId = "";
                    Map<String, Object> metadata = Collections.emptyMap();
                    if (authentication.getDetails() instanceof AuthDetails) {
                        AuthDetails details = (AuthDetails) authentication.getDetails();
                        requestId = details.getRequestId() != null ? details.getRequestId() : "";
                        employeeId = details.getEmployeeId() != null ? details.getEmployeeId() : "";
                        serviceAccountId = details.getServiceAccountId() != null ? details.getServiceAccountId() : "";
                        metadata = details.getMetadata() != null ? details.getMetadata() : Collections.emptyMap();
                    }

                    return AuthInfo.builder()
                            .partyId(partyId)
                            .employeeId(employeeId)
                            .serviceAccountId(serviceAccountId)
                            .roles(roles)
                            .scopes(scopes)
                            .requestId(requestId)
                            .metadata(metadata)
                            .build();
                });
    }

    /**
     * Checks if the current user has the CUSTOMER role.
     *
     * @return true if the user has the CUSTOMER role
     */
    public boolean isCustomer() {
        return roles.contains("CUSTOMER");
    }

    /**
     * Checks if the current user has any of the employee roles.
     *
     * @return true if the user has any of the employee roles
     */
    public boolean isEmployee() {
        return roles.contains("ADMIN") || 
               roles.contains("CUSTOMER_SUPPORT") || 
               roles.contains("SUPERVISOR") || 
               roles.contains("MANAGER") ||
               roles.contains("BRANCH_STAFF");
    }

    /**
     * Checks if the current user has the SERVICE_ACCOUNT role.
     *
     * @return true if the user has the SERVICE_ACCOUNT role
     */
    public boolean isServiceAccount() {
        return roles.contains("SERVICE_ACCOUNT");
    }

    /**
     * Checks if the current user has the ADMIN role.
     *
     * @return true if the user has the ADMIN role
     */
    public boolean isAdmin() {
        return roles.contains("ADMIN");
    }

    /**
     * Checks if the current user has the CUSTOMER_SUPPORT role.
     *
     * @return true if the user has the CUSTOMER_SUPPORT role
     */
    public boolean isCustomerSupport() {
        return roles.contains("CUSTOMER_SUPPORT");
    }

    /**
     * Checks if the current user has the SUPERVISOR role.
     *
     * @return true if the user has the SUPERVISOR role
     */
    public boolean isSupervisor() {
        return roles.contains("SUPERVISOR");
    }

    /**
     * Checks if the current user has the MANAGER role.
     *
     * @return true if the user has the MANAGER role
     */
    public boolean isManager() {
        return roles.contains("MANAGER");
    }

    /**
     * Checks if the current user has the specified role.
     *
     * @param role the role to check
     * @return true if the user has the specified role
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /**
     * Checks if the current user has any of the specified roles.
     *
     * @param rolesToCheck the roles to check
     * @return true if the user has any of the specified roles
     */
    public boolean hasAnyRole(String... rolesToCheck) {
        for (String role : rolesToCheck) {
            if (roles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the current user has the specified scope.
     *
     * @param scope the scope to check
     * @return true if the user has the specified scope
     */
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /**
     * Checks if the current user has any of the specified scopes.
     *
     * @param scopesToCheck the scopes to check
     * @return true if the user has any of the specified scopes
     */
    public boolean hasAnyScope(String... scopesToCheck) {
        for (String scope : scopesToCheck) {
            if (scopes.contains(scope)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the current user has all of the specified roles.
     *
     * @param rolesToCheck the roles to check
     * @return true if the user has all of the specified roles
     */
    public boolean hasAllRoles(String... rolesToCheck) {
        for (String role : rolesToCheck) {
            if (!roles.contains(role)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if the current user has all of the specified scopes.
     *
     * @param scopesToCheck the scopes to check
     * @return true if the user has all of the specified scopes
     */
    public boolean hasAllScopes(String... scopesToCheck) {
        for (String scope : scopesToCheck) {
            if (!scopes.contains(scope)) {
                return false;
            }
        }
        return true;
    }

    // ========== Metadata Utility Methods ==========

    /**
     * Gets a metadata value by key.
     *
     * @param key the metadata key
     * @return an Optional containing the value if present, empty otherwise
     */
    public Optional<Object> getMetadata(String key) {
        return Optional.ofNullable(metadata.get(key));
    }

    /**
     * Gets a metadata value by key and casts it to the specified type.
     *
     * @param key the metadata key
     * @param type the expected type of the value
     * @param <T> the type parameter
     * @return an Optional containing the typed value if present and of the correct type, empty otherwise
     */
    @SuppressWarnings("unchecked")
    public <T> Optional<T> getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        if (value != null && type.isInstance(value)) {
            return Optional.of((T) value);
        }
        return Optional.empty();
    }

    /**
     * Gets a metadata value by key as a String.
     *
     * @param key the metadata key
     * @return an Optional containing the String value if present, empty otherwise
     */
    public Optional<String> getMetadataAsString(String key) {
        return getMetadata(key, String.class);
    }

    /**
     * Gets a metadata value by key as an Integer.
     *
     * @param key the metadata key
     * @return an Optional containing the Integer value if present, empty otherwise
     */
    public Optional<Integer> getMetadataAsInteger(String key) {
        return getMetadata(key, Integer.class);
    }

    /**
     * Gets a metadata value by key as a Boolean.
     *
     * @param key the metadata key
     * @return an Optional containing the Boolean value if present, empty otherwise
     */
    public Optional<Boolean> getMetadataAsBoolean(String key) {
        return getMetadata(key, Boolean.class);
    }

    /**
     * Checks if a metadata key exists.
     *
     * @param key the metadata key
     * @return true if the key exists in metadata, false otherwise
     */
    public boolean hasMetadata(String key) {
        return metadata.containsKey(key);
    }

    /**
     * Gets all metadata keys.
     *
     * @return a Set containing all metadata keys
     */
    public Set<String> getMetadataKeys() {
        return metadata.keySet();
    }

    /**
     * Checks if metadata is empty.
     *
     * @return true if metadata is empty, false otherwise
     */
    public boolean isMetadataEmpty() {
        return metadata.isEmpty();
    }

    /**
     * Gets the size of metadata.
     *
     * @return the number of metadata entries
     */
    public int getMetadataSize() {
        return metadata.size();
    }
}
