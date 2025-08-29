package com.firefly.common.auth.service;

import com.firefly.common.auth.model.AuthInfo;
import reactor.core.publisher.Mono;

/**
 * Interface for validators that check if a user has access to a specific resource.
 * Implementations of this interface should be annotated with @AccessValidatorFor
 * to specify the resource type they validate.
 */
public interface AccessValidator {
    
    /**
     * Gets the name of the resource type that this validator is responsible for.
     * This method is used as a fallback if the @AccessValidatorFor annotation is not present.
     *
     * @return the resource type name
     */
    String getResourceName();
    
    /**
     * Validates if the user has access to the specified resource.
     *
     * @param resourceId the ID of the resource
     * @param authInfo the authentication information
     * @return a Mono that emits true if the user has access, false otherwise
     */
    Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo);
}