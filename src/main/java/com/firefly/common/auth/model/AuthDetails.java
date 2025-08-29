package com.firefly.common.auth.model;

import lombok.Builder;
import lombok.Data;

/**
 * Class to store additional authentication details.
 */
@Data
@Builder
public class AuthDetails {
    private final String requestId;
    private final String employeeId;
    private final String serviceAccountId;
}
