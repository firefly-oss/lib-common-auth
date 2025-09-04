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


package com.firefly.common.auth.service.validator;

import com.firefly.common.auth.annotation.AccessValidatorFor;
import com.firefly.common.auth.model.AuthInfo;
import com.firefly.common.auth.service.AccessValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Validator for account resources.
 * This validator checks if the user is the owner of the account.
 */
@Component
@AccessValidatorFor("account-example")
@Slf4j
public class AccountAccessValidator implements AccessValidator {

    @Override
    public String getResourceName() {
        return "account-example";
    }

    @Override
    public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
        // If the user has any employee role, they have access to all accounts
        if (authInfo.isEmployee()) {
            log.debug("User has employee role, granting access to account: {}", resourceId);
            return Mono.just(true);
        }

        // Check if the user is the owner of the account
        // In a real implementation, this would involve a database query or service call
        // For simplicity, we'll just check if the partyId matches the accountId
        boolean isOwner = authInfo.getPartyId().equals(resourceId);
        log.debug("User {} is {} owner of account {}", authInfo.getPartyId(), isOwner ? "the" : "not the", resourceId);
        return Mono.just(isOwner);
    }
}
