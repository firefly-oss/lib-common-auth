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


package com.firefly.common.auth.model;

import lombok.Builder;
import lombok.Data;

import java.util.Collections;
import java.util.Map;

/**
 * Class to store additional authentication details.
 */
@Data
@Builder
public class AuthDetails {
    private final String requestId;
    private final String employeeId;
    private final String serviceAccountId;

    /**
     * Additional metadata that can be used to store custom authentication information.
     * This map can contain any key-value pairs that provide additional context about the user.
     * Examples: department, branch, region, permissions, etc.
     */
    @Builder.Default
    private final Map<String, Object> metadata = Collections.emptyMap();
}
