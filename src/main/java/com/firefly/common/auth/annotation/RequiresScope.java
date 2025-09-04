/*
 * Copyright 2025 Firefly Software Solutions Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.firefly.common.auth.annotation;

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