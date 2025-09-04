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
