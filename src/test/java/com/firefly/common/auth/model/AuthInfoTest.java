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

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AuthInfoTest {

    @Test
    void isCustomer_shouldReturnTrueWhenUserHasCustomerRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean isCustomer = authInfo.isCustomer();

        // Then
        assertTrue(isCustomer);
    }

    @Test
    void isCustomer_shouldReturnFalseWhenUserDoesNotHaveCustomerRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean isCustomer = authInfo.isCustomer();

        // Then
        assertFalse(isCustomer);
    }

    @Test
    void isEmployee_shouldReturnTrueWhenUserHasEmployeeRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("ADMIN"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean isEmployee = authInfo.isEmployee();

        // Then
        assertTrue(isEmployee);
    }

    @Test
    void isEmployee_shouldReturnFalseWhenUserDoesNotHaveEmployeeRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean isEmployee = authInfo.isEmployee();

        // Then
        assertFalse(isEmployee);
    }

    @Test
    void isServiceAccount_shouldReturnTrueWhenUserHasServiceAccountRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("SERVICE_ACCOUNT"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean isServiceAccount = authInfo.isServiceAccount();

        // Then
        assertTrue(isServiceAccount);
    }

    @Test
    void isServiceAccount_shouldReturnFalseWhenUserDoesNotHaveServiceAccountRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean isServiceAccount = authInfo.isServiceAccount();

        // Then
        assertFalse(isServiceAccount);
    }

    @Test
    void hasRole_shouldReturnTrueWhenUserHasSpecifiedRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER", "ADMIN"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean hasRole = authInfo.hasRole("ADMIN");

        // Then
        assertTrue(hasRole);
    }

    @Test
    void hasRole_shouldReturnFalseWhenUserDoesNotHaveSpecifiedRole() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean hasRole = authInfo.hasRole("ADMIN");

        // Then
        assertFalse(hasRole);
    }

    @Test
    void hasAnyRole_shouldReturnTrueWhenUserHasAnyOfSpecifiedRoles() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean hasAnyRole = authInfo.hasAnyRole("ADMIN", "CUSTOMER");

        // Then
        assertTrue(hasAnyRole);
    }

    @Test
    void hasAnyRole_shouldReturnFalseWhenUserDoesNotHaveAnyOfSpecifiedRoles() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean hasAnyRole = authInfo.hasAnyRole("ADMIN", "MANAGER");

        // Then
        assertFalse(hasAnyRole);
    }

    @Test
    void hasScope_shouldReturnTrueWhenUserHasSpecifiedScope() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Set.of("contracts.read", "accounts.write"))
                .build();

        // When
        boolean hasScope = authInfo.hasScope("contracts.read");

        // Then
        assertTrue(hasScope);
    }

    @Test
    void hasScope_shouldReturnFalseWhenUserDoesNotHaveSpecifiedScope() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Set.of("contracts.read"))
                .build();

        // When
        boolean hasScope = authInfo.hasScope("accounts.write");

        // Then
        assertFalse(hasScope);
    }

    @Test
    void hasAnyScope_shouldReturnTrueWhenUserHasAnyOfSpecifiedScopes() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Set.of("contracts.read"))
                .build();

        // When
        boolean hasAnyScope = authInfo.hasAnyScope("accounts.write", "contracts.read");

        // Then
        assertTrue(hasAnyScope);
    }

    @Test
    void hasAnyScope_shouldReturnFalseWhenUserDoesNotHaveAnyOfSpecifiedScopes() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Set.of("contracts.read"))
                .build();

        // When
        boolean hasAnyScope = authInfo.hasAnyScope("accounts.write", "payments.read");

        // Then
        assertFalse(hasAnyScope);
    }

    @Test
    void hasAllRoles_shouldReturnTrueWhenUserHasAllSpecifiedRoles() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER", "ADMIN"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean hasAllRoles = authInfo.hasAllRoles("CUSTOMER", "ADMIN");

        // Then
        assertTrue(hasAllRoles);
    }

    @Test
    void hasAllRoles_shouldReturnFalseWhenUserDoesNotHaveAllSpecifiedRoles() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Set.of("CUSTOMER"))
                .scopes(Collections.emptySet())
                .build();

        // When
        boolean hasAllRoles = authInfo.hasAllRoles("CUSTOMER", "ADMIN");

        // Then
        assertFalse(hasAllRoles);
    }

    @Test
    void hasAllScopes_shouldReturnTrueWhenUserHasAllSpecifiedScopes() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Set.of("contracts.read", "accounts.write"))
                .build();

        // When
        boolean hasAllScopes = authInfo.hasAllScopes("contracts.read", "accounts.write");

        // Then
        assertTrue(hasAllScopes);
    }

    @Test
    void hasAllScopes_shouldReturnFalseWhenUserDoesNotHaveAllSpecifiedScopes() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Set.of("contracts.read"))
                .build();

        // When
        boolean hasAllScopes = authInfo.hasAllScopes("contracts.read", "accounts.write");

        // Then
        assertFalse(hasAllScopes);
    }

    // ========== Metadata Tests ==========

    @Test
    void getMetadata_shouldReturnValueWhenKeyExists() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");
        metadata.put("level", 5);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Optional<Object> department = authInfo.getMetadata("department");
        Optional<Object> level = authInfo.getMetadata("level");

        // Then
        assertTrue(department.isPresent());
        assertEquals("IT", department.get());
        assertTrue(level.isPresent());
        assertEquals(5, level.get());
    }

    @Test
    void getMetadata_shouldReturnEmptyWhenKeyDoesNotExist() {
        // Given
        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(Collections.emptyMap())
                .build();

        // When
        Optional<Object> result = authInfo.getMetadata("nonexistent");

        // Then
        assertFalse(result.isPresent());
    }

    @Test
    void getMetadataWithType_shouldReturnTypedValueWhenCorrectType() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");
        metadata.put("level", 5);
        metadata.put("active", true);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Optional<String> department = authInfo.getMetadata("department", String.class);
        Optional<Integer> level = authInfo.getMetadata("level", Integer.class);
        Optional<Boolean> active = authInfo.getMetadata("active", Boolean.class);

        // Then
        assertTrue(department.isPresent());
        assertEquals("IT", department.get());
        assertTrue(level.isPresent());
        assertEquals(Integer.valueOf(5), level.get());
        assertTrue(active.isPresent());
        assertEquals(Boolean.TRUE, active.get());
    }

    @Test
    void getMetadataWithType_shouldReturnEmptyWhenWrongType() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("level", 5);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Optional<String> levelAsString = authInfo.getMetadata("level", String.class);

        // Then
        assertFalse(levelAsString.isPresent());
    }

    @Test
    void getMetadataAsString_shouldReturnStringValue() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Optional<String> department = authInfo.getMetadataAsString("department");

        // Then
        assertTrue(department.isPresent());
        assertEquals("IT", department.get());
    }

    @Test
    void getMetadataAsInteger_shouldReturnIntegerValue() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("level", 5);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Optional<Integer> level = authInfo.getMetadataAsInteger("level");

        // Then
        assertTrue(level.isPresent());
        assertEquals(Integer.valueOf(5), level.get());
    }

    @Test
    void getMetadataAsBoolean_shouldReturnBooleanValue() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("active", true);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Optional<Boolean> active = authInfo.getMetadataAsBoolean("active");

        // Then
        assertTrue(active.isPresent());
        assertEquals(Boolean.TRUE, active.get());
    }

    @Test
    void hasMetadata_shouldReturnTrueWhenKeyExists() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        boolean hasDepartment = authInfo.hasMetadata("department");
        boolean hasNonexistent = authInfo.hasMetadata("nonexistent");

        // Then
        assertTrue(hasDepartment);
        assertFalse(hasNonexistent);
    }

    @Test
    void getMetadataKeys_shouldReturnAllKeys() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");
        metadata.put("level", 5);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        Set<String> keys = authInfo.getMetadataKeys();

        // Then
        assertEquals(2, keys.size());
        assertTrue(keys.contains("department"));
        assertTrue(keys.contains("level"));
    }

    @Test
    void isMetadataEmpty_shouldReturnCorrectValue() {
        // Given
        AuthInfo emptyMetadata = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(Collections.emptyMap())
                .build();

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");
        AuthInfo withMetadata = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When & Then
        assertTrue(emptyMetadata.isMetadataEmpty());
        assertFalse(withMetadata.isMetadataEmpty());
    }

    @Test
    void getMetadataSize_shouldReturnCorrectSize() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("department", "IT");
        metadata.put("level", 5);

        AuthInfo authInfo = AuthInfo.builder()
                .partyId("user123")
                .roles(Collections.emptySet())
                .scopes(Collections.emptySet())
                .metadata(metadata)
                .build();

        // When
        int size = authInfo.getMetadataSize();

        // Then
        assertEquals(2, size);
    }
}
