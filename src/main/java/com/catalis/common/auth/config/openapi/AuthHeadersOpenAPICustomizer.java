package com.catalis.common.auth.config.openapi;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import org.springdoc.core.customizers.OpenApiCustomizer;

import java.util.Optional;

/**
 * OpenAPI customizer that adds authentication headers to all operations.
 * This customizer adds the following headers to the OpenAPI documentation:
 * - X-Party-ID: identifier of the client (required for CUSTOMER role)
 * - X-Employee-ID: identifier of the employee (required for employee roles)
 * - X-Service-Account-ID: identifier of the service account (required for SERVICE_ACCOUNT role)
 * - X-Auth-Roles: roles of the subject, comma-separated
 * - X-Auth-Scopes: OAuth2 scopes, comma-separated
 * - X-Request-ID: for traceability
 */
public class AuthHeadersOpenAPICustomizer implements OpenApiCustomizer {

    private static final String PARTY_ID_HEADER = "X-Party-ID";
    private static final String EMPLOYEE_ID_HEADER = "X-Employee-ID";
    private static final String SERVICE_ACCOUNT_ID_HEADER = "X-Service-Account-ID";
    private static final String ROLES_HEADER = "X-Auth-Roles";
    private static final String SCOPES_HEADER = "X-Auth-Scopes";
    private static final String REQUEST_ID_HEADER = "X-Request-ID";

    @Override
    public void customise(OpenAPI openApi) {
        openApi.getPaths().forEach((path, pathItem) -> {
            // Process all operations for each path
            processOperation(pathItem.getGet());
            processOperation(pathItem.getPost());
            processOperation(pathItem.getPut());
            processOperation(pathItem.getDelete());
            processOperation(pathItem.getPatch());
            processOperation(pathItem.getHead());
            processOperation(pathItem.getOptions());
            processOperation(pathItem.getTrace());
        });
    }

    private void processOperation(Operation operation) {
        if (operation == null) {
            return;
        }

        // Add all authentication headers
        addHeader(operation, PARTY_ID_HEADER, "Identifier of the client (at least one of X-Party-ID, X-Employee-ID, or X-Service-Account-ID is required)");
        addHeader(operation, EMPLOYEE_ID_HEADER, "Identifier of the employee (at least one of X-Party-ID, X-Employee-ID, or X-Service-Account-ID is required)");
        addHeader(operation, SERVICE_ACCOUNT_ID_HEADER, "Identifier of the service account (at least one of X-Party-ID, X-Employee-ID, or X-Service-Account-ID is required)");
        addHeader(operation, ROLES_HEADER, "Roles of the subject (CUSTOMER, ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF, SERVICE_ACCOUNT), comma-separated (optional)");
        addHeader(operation, SCOPES_HEADER, "OAuth2 scopes like contracts.read, accounts.write, comma-separated (optional)");
        addHeader(operation, REQUEST_ID_HEADER, "Unique identifier for the request, used for traceability (optional)");
    }

    private void addHeader(Operation operation, String headerName, String description) {
        // Check if the header parameter already exists
        Optional<Parameter> existingParam = operation.getParameters() != null ?
                operation.getParameters().stream()
                        .filter(p -> headerName.equals(p.getName()) && "header".equals(p.getIn()))
                        .findFirst() :
                Optional.empty();

        // Add the parameter if it doesn't exist
        if (existingParam.isEmpty()) {
            Parameter headerParam = new Parameter()
                    .name(headerName)
                    .in("header")
                    .description(description)
                    .required(false)
                    .schema(new io.swagger.v3.oas.models.media.StringSchema());

            if (operation.getParameters() == null) {
                operation.setParameters(new java.util.ArrayList<>(java.util.List.of(headerParam)));
            } else {
                // Create a new mutable list with all existing parameters plus the new one
                java.util.List<Parameter> newParameters = new java.util.ArrayList<>(operation.getParameters());
                newParameters.add(headerParam);
                operation.setParameters(newParameters);
            }
        }
    }
}
