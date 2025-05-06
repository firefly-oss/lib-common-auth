package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that requires the user to be the owner of the resource.
 * Methods annotated with @RequiresOwnership will be intercepted by the SecurityInterceptor,
 * which will validate if the current user is the owner of the specified resource.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Secured("ownership")
public @interface RequiresOwnership {

    /**
     * The type of resource being accessed.
     * Examples: "contract", "account", etc.
     */
    String resource();

    /**
     * The index of the parameter that contains the resource ID.
     * This parameter will be extracted from the method arguments.
     * If the parameter is a collection, each item will be validated.
     */
    int paramIndex() default 0;

    /**
     * The name of the parameter that contains the resource ID.
     * This parameter will be extracted from the method arguments.
     * If the parameter is a collection, each item will be validated.
     * This is an alternative to paramIndex and takes precedence if both are specified.
     */
    String paramName() default "";

    /**
     * The access type required.
     * Examples: "read", "write", "delete", etc.
     * This can be used by validators to apply different rules based on the access type.
     */
    String accessType() default "read";

    /**
     * Whether to bypass the check for users with employee roles.
     * If true, users with employee roles (ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF) will automatically pass the check.
     * If false, all users will be subject to the ownership check.
     */
    boolean bypassForBackoffice() default true;
}
