package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that requires the user to have a specific OAuth2 scope.
 * Methods annotated with @RequiresScope will be intercepted by the SecurityInterceptor,
 * which will validate if the current user has the specified scope.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Secured("scope")
public @interface RequiresScope {
    
    /**
     * The scope that the user must have.
     * Examples: "contracts.read", "accounts.write"
     */
    String value();
    
    /**
     * Whether any of the specified scopes is sufficient.
     * If true, the user must have at least one of the specified scopes.
     * If false, the user must have all of the specified scopes.
     */
    boolean anyOf() default true;
}