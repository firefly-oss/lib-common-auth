package com.firefly.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that requires the user to have a specific role.
 * Methods annotated with @RequiresRole will be intercepted by the SecurityInterceptor,
 * which will validate if the current user has the specified role.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Secured("role")
public @interface RequiresRole {

    /**
     * The role that the user must have.
     * Examples: "CUSTOMER", "ADMIN", "CUSTOMER_SUPPORT", "SUPERVISOR", "MANAGER", "BRANCH_STAFF", "SERVICE_ACCOUNT"
     */
    String value();

    /**
     * Whether any of the specified roles is sufficient.
     * If true, the user must have at least one of the specified roles.
     * If false, the user must have all of the specified roles.
     */
    boolean anyOf() default true;
}
