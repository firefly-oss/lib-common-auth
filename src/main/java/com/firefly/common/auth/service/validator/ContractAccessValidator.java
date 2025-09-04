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
 * Validator for contract resources.
 * This validator checks if the user is the owner of the contract.
 */
@Component
@AccessValidatorFor("contract-example")
@Slf4j
public class ContractAccessValidator implements AccessValidator {

    @Override
    public String getResourceName() {
        return "contract-example";
    }

    @Override
    public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
        // If the user has any employee role, they have access to all contracts
        if (authInfo.isEmployee()) {
            log.debug("User has employee role, granting access to contract: {}", resourceId);
            return Mono.just(true);
        }

        // Check if the user is the owner of the contract
        // In a real implementation, this would involve a database query or service call
        // For simplicity, we'll just check if the partyId matches the contractId
        boolean isOwner = authInfo.getPartyId().equals(resourceId);
        log.debug("User {} is {} owner of contract {}", authInfo.getPartyId(), isOwner ? "the" : "not the", resourceId);
        return Mono.just(isOwner);
    }
}
