package com.catalis.common.auth.service.validator;

import com.catalis.common.auth.annotation.AccessValidatorFor;
import com.catalis.common.auth.model.AuthInfo;
import com.catalis.common.auth.service.AccessValidator;
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
