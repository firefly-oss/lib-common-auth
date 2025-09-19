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


package com.firefly.common.auth.service.validator;

import com.firefly.common.auth.annotation.AccessValidatorFor;
import com.firefly.common.auth.model.AuthInfo;
import com.firefly.common.auth.service.AccessValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Enhanced validator for account resources that demonstrates metadata usage.
 * This validator checks if the user is the owner of the account and also
 * considers metadata like department and branch for additional access control.
 */
@Component
@AccessValidatorFor("enhanced-account")
@Slf4j
public class EnhancedAccountAccessValidator implements AccessValidator {

    @Override
    public String getResourceName() {
        return "enhanced-account";
    }

    @Override
    public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
        // If the user has any employee role, they have access to all accounts
        if (authInfo.isEmployee()) {
            log.debug("User has employee role, granting access to account: {}", resourceId);
            return Mono.just(true);
        }

        // Check if the user is the owner of the account
        boolean isOwner = authInfo.getPartyId().equals(resourceId);
        
        if (isOwner) {
            log.debug("User {} is owner of account {}", authInfo.getPartyId(), resourceId);
            return Mono.just(true);
        }

        // Check metadata-based access rules
        return checkMetadataBasedAccess(resourceId, authInfo);
    }

    /**
     * Demonstrates how to use metadata for additional access control logic.
     * This method shows various ways to access and use metadata.
     */
    private Mono<Boolean> checkMetadataBasedAccess(String resourceId, AuthInfo authInfo) {
        log.debug("Checking metadata-based access for user {} to account {}", authInfo.getPartyId(), resourceId);

        // Example 1: Check if user has special access based on department
        Optional<String> department = authInfo.getMetadataAsString("Department");
        if (department.isPresent() && "FINANCE".equals(department.get())) {
            log.debug("User has FINANCE department access, granting access to account: {}", resourceId);
            return Mono.just(true);
        }

        // Example 2: Check if user has high enough level
        Optional<Integer> level = authInfo.getMetadataAsInteger("Level");
        if (level.isPresent() && level.get() >= 8) {
            log.debug("User has high level access ({}), granting access to account: {}", level.get(), resourceId);
            return Mono.just(true);
        }

        // Example 3: Check if user is from the same branch as the account
        Optional<String> userBranch = authInfo.getMetadataAsString("Branch");
        if (userBranch.isPresent()) {
            // In a real implementation, you would query the database to get the account's branch
            String accountBranch = getAccountBranch(resourceId);
            if (userBranch.get().equals(accountBranch)) {
                log.debug("User from branch {} has access to account {} from same branch", userBranch.get(), resourceId);
                return Mono.just(true);
            }
        }

        // Example 4: Check if user has special permissions
        Optional<Boolean> hasSpecialAccess = authInfo.getMetadataAsBoolean("SpecialAccess");
        if (hasSpecialAccess.isPresent() && hasSpecialAccess.get()) {
            log.debug("User has special access flag, granting access to account: {}", resourceId);
            return Mono.just(true);
        }

        // Example 5: Check multiple metadata conditions
        if (authInfo.hasMetadata("Region") && authInfo.hasMetadata("Role")) {
            Optional<String> region = authInfo.getMetadataAsString("Region");
            Optional<String> role = authInfo.getMetadataAsString("Role");
            
            if (region.isPresent() && role.isPresent()) {
                if ("NORTH".equals(region.get()) && "SUPERVISOR".equals(role.get())) {
                    log.debug("User is NORTH region supervisor, granting access to account: {}", resourceId);
                    return Mono.just(true);
                }
            }
        }

        // Example 6: Log all available metadata for debugging
        if (!authInfo.isMetadataEmpty()) {
            log.debug("User {} has metadata: {}", authInfo.getPartyId(), authInfo.getMetadataKeys());
            authInfo.getMetadataKeys().forEach(key -> {
                Optional<Object> value = authInfo.getMetadata(key);
                value.ifPresent(v -> log.debug("  {} = {} ({})", key, v, v.getClass().getSimpleName()));
            });
        }

        // Default: deny access
        log.debug("User {} does not have access to account {} based on ownership or metadata rules", 
                 authInfo.getPartyId(), resourceId);
        return Mono.just(false);
    }

    /**
     * Mock method to simulate getting account branch from database.
     * In a real implementation, this would query the database.
     */
    private String getAccountBranch(String accountId) {
        // Mock implementation - in reality, this would query the database
        if (accountId.startsWith("main")) {
            return "Main";
        } else if (accountId.startsWith("north")) {
            return "North";
        } else if (accountId.startsWith("south")) {
            return "South";
        }
        return "Unknown";
    }
}
