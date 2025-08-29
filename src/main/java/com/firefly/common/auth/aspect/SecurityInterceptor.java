package com.firefly.common.auth.aspect;

import com.firefly.common.auth.annotation.PreAuthorize;
import com.firefly.common.auth.annotation.RequiresExpression;
import com.firefly.common.auth.annotation.RequiresOwnership;
import com.firefly.common.auth.annotation.RequiresRole;
import com.firefly.common.auth.annotation.RequiresScope;
import com.firefly.common.auth.annotation.Secured;
import com.firefly.common.auth.model.AuthInfo;
import com.firefly.common.auth.service.AccessValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;

/**
 * Aspect that intercepts methods annotated with security annotations and enforces security rules.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityInterceptor {

    private final AccessValidationService accessValidationService;
    private final ExpressionParser expressionParser = new SpelExpressionParser();

    /**
     * Intercepts methods annotated with @RequiresRole and validates if the current user has the specified role.
     */
    @Around("@annotation(com.firefly.common.auth.annotation.RequiresRole) || @within(com.firefly.common.auth.annotation.RequiresRole)")
    public Object checkRole(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Get the annotation from the method or class
        RequiresRole requiresRole = AnnotationUtils.findAnnotation(method, RequiresRole.class);
        if (requiresRole == null) {
            requiresRole = AnnotationUtils.findAnnotation(method.getDeclaringClass(), RequiresRole.class);
        }

        final String role = requiresRole.value();
        final boolean anyOf = requiresRole.anyOf();

        return AuthInfo.getCurrent()
                .flatMap(authInfo -> {
                    boolean hasRole = anyOf ? authInfo.hasRole(role) : authInfo.getRoles().contains(role);
                    if (!hasRole) {
                        log.warn("Access denied: user with roles {} does not have required role: {}", authInfo.getRoles(), role);
                        return Mono.error(new AccessDeniedException("Access denied: required role '" + role + "' not found"));
                    }

                    try {
                        Object result = joinPoint.proceed();
                        return handleResult(result);
                    } catch (Throwable e) {
                        return Mono.error(e);
                    }
                });
    }

    /**
     * Intercepts methods annotated with @RequiresScope and validates if the current user has the specified scope.
     */
    @Around("@annotation(com.firefly.common.auth.annotation.RequiresScope) || @within(com.firefly.common.auth.annotation.RequiresScope)")
    public Object checkScope(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Get the annotation from the method or class
        RequiresScope requiresScope = AnnotationUtils.findAnnotation(method, RequiresScope.class);
        if (requiresScope == null) {
            requiresScope = AnnotationUtils.findAnnotation(method.getDeclaringClass(), RequiresScope.class);
        }

        final String scope = requiresScope.value();
        final boolean anyOf = requiresScope.anyOf();

        return AuthInfo.getCurrent()
                .flatMap(authInfo -> {
                    boolean hasScope = anyOf ? authInfo.hasScope(scope) : authInfo.getScopes().contains(scope);
                    if (!hasScope) {
                        log.warn("Access denied: user with scopes {} does not have required scope: {}", authInfo.getScopes(), scope);
                        return Mono.error(new AccessDeniedException("Access denied: required scope '" + scope + "' not found"));
                    }

                    try {
                        Object result = joinPoint.proceed();
                        return handleResult(result);
                    } catch (Throwable e) {
                        return Mono.error(e);
                    }
                });
    }

    /**
     * Intercepts methods annotated with @RequiresOwnership and validates if the current user is the owner of the resource.
     */
    @Around("@annotation(com.firefly.common.auth.annotation.RequiresOwnership)")
    public Object checkOwnership(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        RequiresOwnership requiresOwnership = method.getAnnotation(RequiresOwnership.class);
        final String resourceType = requiresOwnership.resource();
        final String accessType = requiresOwnership.accessType();
        final boolean bypassForBackoffice = requiresOwnership.bypassForBackoffice();

        // Get the resource ID from the method parameters
        String resourceId = null;
        if (!requiresOwnership.paramName().isEmpty()) {
            // Get by parameter name
            Parameter[] parameters = method.getParameters();
            Object[] args = joinPoint.getArgs();
            for (int i = 0; i < parameters.length; i++) {
                if (parameters[i].getName().equals(requiresOwnership.paramName())) {
                    resourceId = args[i].toString();
                    break;
                }
            }
        } else {
            // Get by parameter index
            Object[] args = joinPoint.getArgs();
            if (args.length > requiresOwnership.paramIndex()) {
                resourceId = args[requiresOwnership.paramIndex()].toString();
            }
        }

        if (resourceId == null) {
            log.error("Resource ID parameter not found for method: {}", method.getName());
            return Mono.error(new IllegalArgumentException("Resource ID parameter not found"));
        }

        final String finalResourceId = resourceId;

        return AuthInfo.getCurrent()
                .flatMap(authInfo -> {
                    // If the user has any employee role and bypassForBackoffice is true, allow access
                    if (bypassForBackoffice && authInfo.isEmployee()) {
                        log.debug("User has employee role, bypassing ownership check");
                        try {
                            Object result = joinPoint.proceed();
                            return handleResult(result);
                        } catch (Throwable e) {
                            return Mono.error(e);
                        }
                    }

                    // Validate ownership
                    return accessValidationService.validateAccess(resourceType, finalResourceId, authInfo)
                            .flatMap(hasAccess -> {
                                if (!hasAccess) {
                                    log.warn("Access denied: user {} is not the owner of resource: {} with id: {}", authInfo.getPartyId(), resourceType, finalResourceId);
                                    return Mono.error(new AccessDeniedException("Access denied: user is not the owner of resource '" + resourceType + "' with id '" + finalResourceId + "'"));
                                }

                                try {
                                    Object result = joinPoint.proceed();
                                    return handleResult(result);
                                } catch (Throwable e) {
                                    return Mono.error(e);
                                }
                            });
                });
    }

    /**
     * Intercepts methods annotated with @RequiresExpression and validates if the expression evaluates to true.
     */
    @Around("@annotation(com.firefly.common.auth.annotation.RequiresExpression) || @within(com.firefly.common.auth.annotation.RequiresExpression)")
    public Object checkExpression(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Get the annotation from the method or class
        RequiresExpression requiresExpression = AnnotationUtils.findAnnotation(method, RequiresExpression.class);
        if (requiresExpression == null) {
            requiresExpression = AnnotationUtils.findAnnotation(method.getDeclaringClass(), RequiresExpression.class);
        }

        final String expressionString = requiresExpression.value();
        final Expression expression = expressionParser.parseExpression(expressionString);

        return AuthInfo.getCurrent()
                .flatMap(authInfo -> {
                    // Create evaluation context
                    StandardEvaluationContext context = new StandardEvaluationContext();
                    context.setVariable("authInfo", authInfo);
                    context.setVariable("args", joinPoint.getArgs());
                    context.setVariable("target", joinPoint.getTarget());
                    context.setVariable("method", method);

                    // Evaluate expression
                    Boolean result = expression.getValue(context, Boolean.class);
                    if (result == null || !result) {
                        log.warn("Access denied: expression '{}' evaluated to false for user {}", expressionString, authInfo.getPartyId());
                        return Mono.error(new AccessDeniedException("Access denied: expression '" + expressionString + "' evaluated to false"));
                    }

                    try {
                        Object proceedResult = joinPoint.proceed();
                        return handleResult(proceedResult);
                    } catch (Throwable e) {
                        return Mono.error(e);
                    }
                });
    }

    /**
     * Intercepts methods annotated with @PreAuthorize and validates if the expression evaluates to true.
     */
    @Around("@annotation(com.firefly.common.auth.annotation.PreAuthorize) || @within(com.firefly.common.auth.annotation.PreAuthorize)")
    public Object preAuthorize(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Get the annotation from the method or class
        PreAuthorize preAuthorize = AnnotationUtils.findAnnotation(method, PreAuthorize.class);
        if (preAuthorize == null) {
            preAuthorize = AnnotationUtils.findAnnotation(method.getDeclaringClass(), PreAuthorize.class);
        }

        final String expressionString = preAuthorize.value();
        final Expression expression = expressionParser.parseExpression(expressionString);

        return AuthInfo.getCurrent()
                .flatMap(authInfo -> {
                    // Create evaluation context
                    StandardEvaluationContext context = new StandardEvaluationContext();
                    context.setVariable("authInfo", authInfo);
                    context.setVariable("args", joinPoint.getArgs());
                    context.setVariable("target", joinPoint.getTarget());
                    context.setVariable("method", method);

                    // Register functions
                    try {
                        context.registerFunction("hasRole", 
                                AuthInfo.class.getMethod("hasRole", String.class));
                        context.registerFunction("hasAnyRole", 
                                AuthInfo.class.getMethod("hasAnyRole", String[].class));
                        context.registerFunction("hasScope", 
                                AuthInfo.class.getMethod("hasScope", String.class));
                        context.registerFunction("hasAnyScope", 
                                AuthInfo.class.getMethod("hasAnyScope", String[].class));
                    } catch (NoSuchMethodException e) {
                        log.error("Error registering functions for expression evaluation", e);
                        return Mono.error(new RuntimeException("Error registering functions for expression evaluation", e));
                    }

                    // Evaluate expression
                    Boolean result = expression.getValue(context, Boolean.class);
                    if (result == null || !result) {
                        log.warn("Access denied: expression '{}' evaluated to false for user {} with roles {} and scopes {}", 
                                expressionString, authInfo.getPartyId(), authInfo.getRoles(), authInfo.getScopes());
                        return Mono.error(new AccessDeniedException("Access denied: expression '" + expressionString + "' evaluated to false"));
                    }

                    try {
                        Object proceedResult = joinPoint.proceed();
                        return handleResult(proceedResult);
                    } catch (Throwable e) {
                        return Mono.error(e);
                    }
                });
    }

    /**
     * Handles the result of the method execution.
     * If the result is a Mono, returns it as is.
     * If the result is a Flux, wraps it in a Mono.
     * Otherwise, wraps it in a Mono.just().
     */
    private Mono<?> handleResult(Object result) {
        if (result instanceof Mono) {
            return (Mono<?>) result;
        } else if (result instanceof Flux) {
            return Mono.just(result);
        } else {
            return Mono.just(result);
        }
    }
}
