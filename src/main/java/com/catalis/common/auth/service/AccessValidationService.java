package com.catalis.common.auth.service;

import com.catalis.common.auth.model.AuthInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Service that defines pluggable/extensible validation logic according to the resource type.
 * This service is used by the AccessControlAspect to validate if the current user has access to the specified resource.
 * It delegates validation to the appropriate validator based on the resource type.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AccessValidationService {

    private final AccessValidatorRegistry validatorRegistry;

    /**
     * Validates if the current user has access to the specified resource.
     *
     * @param resourceType the type of resource
     * @param resourceId   the ID of the resource
     * @param authInfo     the authentication information
     * @return a Mono that emits true if the user has access, false otherwise
     * @throws AccessDeniedException if no validator is found for the resource type
     */
    public Mono<Boolean> validateAccess(String resourceType, String resourceId, AuthInfo authInfo) {
        // If the user has any employee role, they have access to all resources
        if (authInfo.isEmployee()) {
            log.debug("User has employee role, granting access to {}: {}", resourceType, resourceId);
            return Mono.just(true);
        }

        // Get the validator for the resource type
        AccessValidator validator = validatorRegistry.getValidator(resourceType);
        if (validator == null) {
            log.error("No validator found for resource type: {}", resourceType);
            return Mono.error(new AccessDeniedException("No validator found for resource type: " + resourceType));
        }

        // Delegate validation to the validator
        log.debug("Validating access to {}: {} for user: {}", resourceType, resourceId, authInfo.getPartyId());
        return validator.canAccess(resourceId, authInfo);
    }
}
