package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Meta-annotation that marks other annotations as security annotations.
 * Annotations marked with @Secured will be processed by the SecurityInterceptor.
 */
@Target(ElementType.ANNOTATION_TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Secured {
    
    /**
     * The type of security check to perform.
     * This is used by the SecurityInterceptor to determine how to process the annotation.
     */
    String value() default "";
}