package com.firefly.common.auth.model;

import org.junit.jupiter.api.Test;

import java.util.Collections;
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
}
