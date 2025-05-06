package com.catalis.common.auth.service;

import com.catalis.common.auth.annotation.AccessValidatorFor;
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
