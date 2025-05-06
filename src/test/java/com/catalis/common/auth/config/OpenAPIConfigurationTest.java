package com.catalis.common.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.parameters.Parameter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Import(OpenAPIConfiguration.class)
@ActiveProfiles("test")
class OpenAPIConfigurationTest {

    @Autowired
    private OpenAPI openAPI;

    @Test
    void shouldCreateOpenAPIBean() {
        assertNotNull(openAPI);
    }

    @Test
    void shouldIncludeAuthenticationHeaders() {
        // Check that all required headers are defined in the components
        assertNotNull(openAPI.getComponents());
        assertNotNull(openAPI.getComponents().getParameters());

        // Check for X-Party-ID header
        Parameter partyIdHeader = openAPI.getComponents().getParameters().get("X-Party-ID");
        assertNotNull(partyIdHeader);
        assertEquals("X-Party-ID", partyIdHeader.getName());
        assertTrue(partyIdHeader.getDescription().contains("CUSTOMER"));

        // Check for X-Employee-ID header
        Parameter employeeIdHeader = openAPI.getComponents().getParameters().get("X-Employee-ID");
        assertNotNull(employeeIdHeader);
        assertEquals("X-Employee-ID", employeeIdHeader.getName());
        assertTrue(employeeIdHeader.getDescription().contains("employee roles"));

        // Check for X-Service-Account-ID header
        Parameter serviceAccountIdHeader = openAPI.getComponents().getParameters().get("X-Service-Account-ID");
        assertNotNull(serviceAccountIdHeader);
        assertEquals("X-Service-Account-ID", serviceAccountIdHeader.getName());
        assertTrue(serviceAccountIdHeader.getDescription().contains("SERVICE_ACCOUNT"));

        // Check for X-Auth-Roles header
        Parameter rolesHeader = openAPI.getComponents().getParameters().get("X-Auth-Roles");
        assertNotNull(rolesHeader);
        assertEquals("X-Auth-Roles", rolesHeader.getName());
        assertTrue(rolesHeader.getDescription().contains("Roles"));

        // Check for X-Auth-Scopes header
        Parameter scopesHeader = openAPI.getComponents().getParameters().get("X-Auth-Scopes");
        assertNotNull(scopesHeader);
        assertEquals("X-Auth-Scopes", scopesHeader.getName());
        assertTrue(scopesHeader.getDescription().contains("OAuth2"));

        // Check for X-Request-ID header
        Parameter requestIdHeader = openAPI.getComponents().getParameters().get("X-Request-ID");
        assertNotNull(requestIdHeader);
        assertEquals("X-Request-ID", requestIdHeader.getName());
        assertTrue(requestIdHeader.getDescription().contains("traceability"));
    }
}
