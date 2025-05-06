package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark methods that require access control.
 * This annotation specifies the resource type and the parameter that contains the resource ID.
 * Methods annotated with @CheckAccess will be intercepted by the AccessControlAspect,
 * which will validate if the current user has access to the specified resource.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface CheckAccess {
    
    /**
     * The type of resource being accessed.
     * Examples: "contract", "account", etc.
     */
    String resource();
    
    /**
     * The name of the parameter that contains the resource ID.
     * This parameter will be extracted from the method arguments.
     */
    String idParam();
}