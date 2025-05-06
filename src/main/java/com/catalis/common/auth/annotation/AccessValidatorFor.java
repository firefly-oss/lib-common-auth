package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark classes that implement the AccessValidator interface.
 * This annotation specifies the resource type that the validator is responsible for.
 * Classes annotated with @AccessValidatorFor will be automatically discovered and registered
 * by the AccessValidatorRegistry.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface AccessValidatorFor {
    
    /**
     * The type of resource that this validator is responsible for.
     * Examples: "contract", "account", etc.
     */
    String value();
}