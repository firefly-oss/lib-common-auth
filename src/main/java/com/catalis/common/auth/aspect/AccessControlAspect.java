package com.catalis.common.auth.aspect;

import com.catalis.common.auth.annotation.CheckAccess;
import com.catalis.common.auth.model.AuthInfo;
import com.catalis.common.auth.service.AccessValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

/**
 * Aspect that intercepts methods annotated with @CheckAccess and validates if the current user has access to the specified resource.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AccessControlAspect {

    private final AccessValidationService accessValidationService;

    /**
     * Intercepts methods annotated with @CheckAccess and validates if the current user has access to the specified resource.
     *
     * @param joinPoint the join point
     * @return the result of the method execution
     * @throws Throwable if an error occurs
     */
    @Around("@annotation(com.catalis.common.auth.annotation.CheckAccess)")
    public Object checkAccess(ProceedingJoinPoint joinPoint) throws Throwable {
        // Get method signature
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Get @CheckAccess annotation
        final CheckAccess checkAccess = method.getAnnotation(CheckAccess.class);
        final String resourceType = checkAccess.resource();
        final String idParamName = checkAccess.idParam();

        // Get method parameters
        final Parameter[] parameters = method.getParameters();
        final Object[] args = joinPoint.getArgs();

        // Find the parameter with the specified name
        String resourceId = null;
        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].getName().equals(idParamName)) {
                resourceId = args[i].toString();
                break;
            }
        }

        if (resourceId == null) {
            log.error("Parameter with name '{}' not found in method {}", idParamName, method.getName());
            throw new IllegalArgumentException("Parameter with name '" + idParamName + "' not found");
        }

        final String finalResourceId = resourceId;

        // Get current AuthInfo
        return AuthInfo.getCurrent()
                .flatMap(authInfo -> {
                    log.debug("Checking access for resource type: {}, resourceId: {}, user: {}", resourceType, finalResourceId, authInfo.getPartyId());

                    // Validate access
                    return accessValidationService.validateAccess(resourceType, finalResourceId, authInfo)
                            .flatMap(hasAccess -> {
                                if (!hasAccess) {
                                    log.warn("Access denied for resource type: {}, resourceId: {}, user: {}", resourceType, finalResourceId, authInfo.getPartyId());
                                    return Mono.error(new AccessDeniedException("Access denied to resource: " + resourceType + " with id: " + finalResourceId));
                                }

                                log.debug("Access granted for resource type: {}, resourceId: {}, user: {}", resourceType, finalResourceId, authInfo.getPartyId());

                                try {
                                    // Proceed with the method execution
                                    Object result = joinPoint.proceed();

                                    // Handle reactive return types
                                    if (result instanceof Mono) {
                                        return (Mono<?>) result;
                                    } else if (result instanceof Flux) {
                                        return Mono.just(result);
                                    } else {
                                        return Mono.just(result);
                                    }
                                } catch (Throwable e) {
                                    return Mono.error(e);
                                }
                            });
                })
                .onErrorMap(e -> {
                    if (e instanceof AccessDeniedException) {
                        return e;
                    }
                    log.error("Error checking access", e);
                    return new RuntimeException("Error checking access", e);
                });
    }
}
