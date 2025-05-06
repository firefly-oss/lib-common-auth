package com.catalis.common.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.parameters.HeaderParameter;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for OpenAPI documentation.
 * This class sets up the OpenAPI documentation for the API, including global header parameters.
 */
@Configuration
public class OpenAPIConfiguration {

    // Header constants from AuthContextWebFilter
    private static final String PARTY_ID_HEADER = "X-Party-ID";
    private static final String EMPLOYEE_ID_HEADER = "X-Employee-ID";
    private static final String SERVICE_ACCOUNT_ID_HEADER = "X-Service-Account-ID";
    private static final String ROLES_HEADER = "X-Auth-Roles";
    private static final String SCOPES_HEADER = "X-Auth-Scopes";
    private static final String REQUEST_ID_HEADER = "X-Request-ID";

    /**
     * Configures the OpenAPI documentation.
     *
     * @return the OpenAPI configuration
     */
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Firefly Authorization API")
                        .version("1.0.0")
                        .description("API documentation for the Firefly Authorization library")
                        .license(new License().name("Apache 2.0").url("https://www.apache.org/licenses/LICENSE-2.0")))
                .components(new Components()
                        .addSecuritySchemes("bearer-jwt", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT token authentication"))
                        .addParameters(PARTY_ID_HEADER, createHeaderParameter(PARTY_ID_HEADER, "Identifier of the client (required for CUSTOMER role)"))
                        .addParameters(EMPLOYEE_ID_HEADER, createHeaderParameter(EMPLOYEE_ID_HEADER, "Identifier of the employee (required for employee roles: ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF)"))
                        .addParameters(SERVICE_ACCOUNT_ID_HEADER, createHeaderParameter(SERVICE_ACCOUNT_ID_HEADER, "Identifier of the service account (required for SERVICE_ACCOUNT role)"))
                        .addParameters(ROLES_HEADER, createHeaderParameter(ROLES_HEADER, "Roles of the subject (CUSTOMER, ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF, SERVICE_ACCOUNT), comma-separated"))
                        .addParameters(SCOPES_HEADER, createHeaderParameter(SCOPES_HEADER, "OAuth2 scopes like contracts.read, accounts.write, comma-separated"))
                        .addParameters(REQUEST_ID_HEADER, createHeaderParameter(REQUEST_ID_HEADER, "Request ID for traceability")));
    }

    /**
     * Creates a header parameter for OpenAPI documentation.
     *
     * @param name the name of the header
     * @param description the description of the header
     * @return the header parameter
     */
    private Parameter createHeaderParameter(String name, String description) {
        return new HeaderParameter()
                .name(name)
                .description(description)
                .required(false)
                .schema(new io.swagger.v3.oas.models.media.StringSchema());
    }

    /**
     * Customizes operations to add global header parameters.
     *
     * @return the operation customizer
     */
    @Bean
    public OperationCustomizer operationCustomizer() {
        return (operation, handlerMethod) -> {
            // Add header parameters to all operations
            operation.addParametersItem(new Parameter().$ref("#/components/parameters/" + PARTY_ID_HEADER));
            operation.addParametersItem(new Parameter().$ref("#/components/parameters/" + EMPLOYEE_ID_HEADER));
            operation.addParametersItem(new Parameter().$ref("#/components/parameters/" + SERVICE_ACCOUNT_ID_HEADER));
            operation.addParametersItem(new Parameter().$ref("#/components/parameters/" + ROLES_HEADER));
            operation.addParametersItem(new Parameter().$ref("#/components/parameters/" + SCOPES_HEADER));
            operation.addParametersItem(new Parameter().$ref("#/components/parameters/" + REQUEST_ID_HEADER));
            return operation;
        };
    }
}
