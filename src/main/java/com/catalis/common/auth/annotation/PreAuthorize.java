package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that requires a custom SpEL expression to evaluate to true.
 * This annotation is similar to Spring Security's @PreAuthorize but works with reactive code.
 * Methods annotated with @PreAuthorize will be intercepted by the SecurityInterceptor,
 * which will evaluate the specified expression and allow access if it evaluates to true.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Secured("preAuthorize")
public @interface PreAuthorize {
    
    /**
     * The SpEL expression to evaluate.
     * The expression can access the following variables:
     * - #authInfo: the current AuthInfo object
     * - #args: the method arguments
     * - #target: the target object
     * - #method: the method being invoked
     * 
     * Common expressions:
     * - hasRole('ROLE_NAME'): checks if the user has the specified role
     * - hasAnyRole('ROLE1', 'ROLE2'): checks if the user has any of the specified roles
     * - hasScope('SCOPE_NAME'): checks if the user has the specified scope
     * - hasAnyScope('SCOPE1', 'SCOPE2'): checks if the user has any of the specified scopes
     * - isOwner('resource', #resourceId): checks if the user is the owner of the specified resource
     */
    String value();
}