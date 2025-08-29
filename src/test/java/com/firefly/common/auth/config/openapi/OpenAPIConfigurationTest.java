package com.firefly.common.auth.config.openapi;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest(
    classes = {OpenAPIConfiguration.class},
    properties = {"springdoc.api-docs.enabled=true"}
)
class OpenAPIConfigurationTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private AuthHeadersOpenAPICustomizer customizer;

    @Test
    void testAuthHeadersOpenAPICustomizerBeanExists() {
        // Verify that the bean is created and available in the context
        assertNotNull(customizer);
    }

    @Test
    void testCustomizerAddsHeaders() {
        // Create a mock OpenAPI object
        OpenAPI openAPI = Mockito.mock(OpenAPI.class);
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        Operation operation = new Operation();
        operation.setParameters(new java.util.ArrayList<>());
        pathItem.setGet(operation);
        paths.addPathItem("/test", pathItem);

        when(openAPI.getPaths()).thenReturn(paths);

        // Call the customizer
        customizer.customise(openAPI);

        // Verify that headers were added to the operation
        assertNotNull(operation.getParameters());
        // We expect 6 headers to be added
        assert(operation.getParameters().size() == 6);

        // Verify that the headers have the expected names
        assert(operation.getParameters().stream()
                .anyMatch(p -> "X-Party-ID".equals(p.getName())));
        assert(operation.getParameters().stream()
                .anyMatch(p -> "X-Employee-ID".equals(p.getName())));
        assert(operation.getParameters().stream()
                .anyMatch(p -> "X-Service-Account-ID".equals(p.getName())));
        assert(operation.getParameters().stream()
                .anyMatch(p -> "X-Auth-Roles".equals(p.getName())));
        assert(operation.getParameters().stream()
                .anyMatch(p -> "X-Auth-Scopes".equals(p.getName())));
        assert(operation.getParameters().stream()
                .anyMatch(p -> "X-Request-ID".equals(p.getName())));
    }
}
