package com.catalis.common.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that requires a custom SpEL expression to evaluate to true.
 * Methods annotated with @RequiresExpression will be intercepted by the SecurityInterceptor,
 * which will evaluate the specified expression and allow access if it evaluates to true.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Secured("expression")
public @interface RequiresExpression {
    
    /**
     * The SpEL expression to evaluate.
     * The expression can access the following variables:
     * - #authInfo: the current AuthInfo object
     * - #args: the method arguments
     * - #result: the method result (only available in @AfterReturning advice)
     * - #target: the target object
     * - #method: the method being invoked
     */
    String value();
}