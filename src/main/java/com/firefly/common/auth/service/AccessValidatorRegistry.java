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


package com.firefly.common.auth.service;

import com.firefly.common.auth.annotation.AccessValidatorFor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

/**
 * Registry for access validators.
 * This class discovers and registers all beans that implement the AccessValidator interface
 * at application startup.
 */
@Component
@Slf4j
public class AccessValidatorRegistry {

    private final ApplicationContext applicationContext;
    private final Map<String, AccessValidator> validators = new HashMap<>();

    @Autowired
    public AccessValidatorRegistry(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    /**
     * Initializes the registry by discovering and registering all AccessValidator beans.
     */
    @PostConstruct
    public void init() {
        Map<String, AccessValidator> validatorBeans = applicationContext.getBeansOfType(AccessValidator.class);
        log.info("Found {} AccessValidator beans", validatorBeans.size());

        validatorBeans.forEach((beanName, validator) -> {
            String resourceName = getResourceName(validator);
            validators.put(resourceName, validator);
            log.info("Registered validator for resource type: {} (bean: {})", resourceName, beanName);
        });
    }

    /**
     * Gets the resource name for a validator.
     * First checks for the @AccessValidatorFor annotation, then falls back to the getResourceName() method.
     *
     * @param validator the validator
     * @return the resource name
     */
    private String getResourceName(AccessValidator validator) {
        Class<?> validatorClass = validator.getClass();
        AccessValidatorFor annotation = validatorClass.getAnnotation(AccessValidatorFor.class);

        if (annotation != null) {
            return annotation.value();
        }

        return validator.getResourceName();
    }

    /**
     * Gets a validator for the specified resource type.
     *
     * @param resourceType the resource type
     * @return the validator, or null if no validator is registered for the resource type
     */
    public AccessValidator getValidator(String resourceType) {
        return validators.get(resourceType);
    }

    /**
     * Checks if a validator is registered for the specified resource type.
     *
     * @param resourceType the resource type
     * @return true if a validator is registered, false otherwise
     */
    public boolean hasValidator(String resourceType) {
        return validators.containsKey(resourceType);
    }
}
