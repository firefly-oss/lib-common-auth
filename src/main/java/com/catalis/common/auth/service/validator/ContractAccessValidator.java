package com.catalis.common.auth.service.validator;

import com.catalis.common.auth.annotation.AccessValidatorFor;
import com.catalis.common.auth.model.AuthInfo;
import com.catalis.common.auth.service.AccessValidator;
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
