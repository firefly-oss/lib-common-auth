package com.firefly.common.auth.aspect;

import com.firefly.common.auth.model.AuthInfo;
import com.firefly.common.auth.service.AccessValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Aspect for access control validation.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AccessControlAspect {

    private final AccessValidationService accessValidationService;
}
