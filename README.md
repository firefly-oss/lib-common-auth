# Firefly Authorization Library

A comprehensive, reactive authentication and authorization library for Spring Boot 3 + WebFlux applications that provides header-based authentication and fine-grained access control.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Component Architecture](#component-architecture)
  - [Authentication Flow](#authentication-flow)
  - [Class Diagram](#class-diagram)
- [How It Works](#how-it-works)
  - [Authentication Process](#authentication-process)
  - [Authorization Process](#authorization-process)
  - [Resource Ownership Validation](#resource-ownership-validation)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Enable the Library](#1-enable-the-library)
  - [Access Authentication Information](#2-access-the-current-authentication-information)
  - [Secure Methods with Annotations](#3-secure-methods-with-annotations)
  - [Create Custom Validators](#4-create-custom-validators)
- [Annotation Reference](#annotation-reference)
  - [Security Annotations](#security-annotations)
  - [Validator Annotations](#validator-annotations)
  - [Meta Annotations](#meta-annotations)
- [Roles Documentation](ROLES.md)
- [Migration Guide](#migration-guide)
- [Advanced Usage](#advanced-usage)
- [OpenAPI Documentation](#openapi-documentation)
- [Performance Considerations and Best Practices](#performance-considerations-and-best-practices)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

Firefly Authorization is a reactive authorization library that delegates authentication to the perimeter (Istio/API Gateway) and applies fine-grained access control at the resource level within services using annotations and aspects. It eliminates the need to duplicate security logic in controllers or services, providing a consistent and maintainable approach to security across your microservices architecture.

## Architecture

### Component Architecture

The following diagram shows the main components of the Firefly Authorization Library and how they interact with each other:

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                             ╔══════════════════════════╗                            │
│                             ║   API Gateway / Istio    ║                            │
│                             ╚═══════════════╦══════════╝                            │
│                                             ║                                       │
│                                             ║  HTTP Headers                         │
│                                             ║  (X-Party-ID, X-Employee-ID,          │
│                                             ║   X-Auth-Roles, etc.)                 │
│                                             ▼                                       │
│ ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│ │                           Spring Boot Application                               │ │
│ │                                                                                 │ │
│ │  ┌───────────────────────────────────────────────────────────────────────────┐  │ │
│ │  │                      Firefly Authorization Library                        │  │ │
│ │  │                                                                           │  │ │
│ │  │  ┌─────────────────┐           ┌────────────────────────────────┐         │  │ │
│ │  │  │                 │           │                                │         │  │ │
│ │  │  │AuthContextFilter│──────────▶│  ReactiveSecurityContextHolder │         │  │ │
│ │  │  │                 │           │                                │         │  │ │
│ │  │  └─────────────────┘           └────────────────┬───────────────┘         │  │ │
│ │  │                                                 │                         │  │ │
│ │  │                                                 │                         │  │ │
│ │  │  ┌─────────────────┐                            │                         │  │ │
│ │  │  │   Controller    │                            │                         │  │ │
│ │  │  │                 │                            │                         │  │ │
│ │  │  │ @RequiresRole   │◀────┐                      │                         │  │ │
│ │  │  │ @RequiresScope  │     │                      │                         │  │ │
│ │  │  │ @PreAuthorize   │     │                      │                         │  │ │
│ │  │  └─────────────────┘     │                      │                         │  │ │
│ │  │                          │                      │                         │  │ │
│ │  │  ┌─────────────────┐     │    ┌─────────────────▼──────────────────┐      │  │ │
│ │  │  │    Service      │     │    │                                    │      │  │ │
│ │  │  │                 │     │    │              AuthInfo              │      │  │ │
│ │  │  │ @RequiresRole   │     │    │                                    │      │  │ │
│ │  │  │ @RequiresScope  │     │    │ ┌────────────────────────────────┐ │      │  │ │
│ │  │  │ @PreAuthorize   │     │    │ │ - getPartyId()                 │ │      │  │ │
│ │  │  │                 │     │    │ │ - getEmployeeId()              │ │      │  │ │
│ │  │  │ @RequiresOwner  │     │    │ │ - getRoles(), getScopes()      │ │      │  │ │
│ │  │  └────────┬────────┘     │    │ │ - isAdmin(), isCustomer(), etc.│ │      │  │ │
│ │  │           │              │    │ └────────────────────────────────┘ │      │  │ │
│ │  │           │              │    └─────────────────┬──────────────────┘      │  │ │
│ │  │           │              │                      │                         │  │ │
│ │  │  ┌────────▼────────┐     │    ┌─────────────────▼──────────────────┐      │  │ │
│ │  │  │                 │     │    │                                    │      │  │ │
│ │  │  │SecurityInterceptor────┘    │    AccessValidationService         │      │  │ │
│ │  │  │                 │          │                                    │      │  │ │
│ │  │  └────────┬────────┘          └─────────────────┬──────────────────┘      │  │ │
│ │  │           │                                     │                         │  │ │
│ │  │           │                   ┌─────────────────▼──────────────────┐      │  │ │
│ │  │           │                   │                                    │      │  │ │
│ │  │           └───────────────────▶    AccessValidatorRegistry         │      │  │ │
│ │  │                               │                                    │      │  │ │
│ │  │                               └─────────────────┬──────────────────┘      │  │ │
│ │  │                                                 │                         │  │ │
│ │  │                               ┌─────────────────▼──────────────────┐      │  │ │
│ │  │                               │       AccessValidators             │      │  │ │
│ │  │                               │                                    │      │  │ │
│ │  │                               │ ┌────────────────────────────────┐ │      │  │ │
│ │  │                               │ │ - ContractAccessValidator      │ │      │  │ │
│ │  │                               │ │ - AccountAccessValidator       │ │      │  │ │
│ │  │                               │ │ - Custom Validators            │ │      │  │ │
│ │  │                               │ └────────────────────────────────┘ │      │  │ │
│ │  │                               └────────────────────────────────────┘      │  │ │
│ │  │                                                                           │  │ │
│ │  └───────────────────────────────────────────────────────────────────────────┘  │ │
│ │                                                                                 │ │
│ └─────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

The following diagram shows the authentication flow when a request is received:

```
┌──────────┐     ┌───────────────────┐     ┌─────────────────────┐
│  Client  │────▶│ API Gateway/Istio │────▶│ Spring Boot App     │
└──────────┘     └───────────────────┘     └──────────┬──────────┘
                                                      │
                                                      │ HTTP Request with Headers
                                                      │ (X-Party-ID, X-Employee-ID, 
                                                      │  X-Auth-Roles, etc.)
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AuthContextWebFilter                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Extract headers from request                                             │
│ 2. Determine user type (Customer, Employee, Service Account)                │
│ 3. Validate required headers based on user type                             │
│ 4. Build authorities list from roles and scopes                             │
│ 5. Create Authentication object with appropriate principal                  │
│ 6. Store Authentication in ReactiveSecurityContextHolder                    │
└───────────────────────────────────────────────────────────────────────────┬─┘
                                                                            │
                                                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Controller/Service Method                           │
│                                                                             │
│  @RequiresRole("ADMIN")                                                     │
│  @RequiresScope("contracts.read")                                           │
│  @RequiresOwnership(resource = "contract", paramName = "contractId")        │
│  public Mono<Contract> getContractById(String contractId) { ... }           │
└───────────────────────────────────────────────────────────────────────────┬─┘
                                                                            │
                                                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SecurityInterceptor                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Intercept method call                                                    │
│ 2. Get current AuthInfo from ReactiveSecurityContextHolder                  │
│ 3. Check if user has required role/scope                                    │
│ 4. For ownership checks, extract resource ID from method parameters         │
│ 5. Call AccessValidationService to validate ownership                       │
│ 6. If all checks pass, proceed with method execution                        │
│ 7. Otherwise, throw AccessDeniedException                                   │
└───────────────────────────────────────────────────────────────────────────┬─┘
                                                                            │
                                                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AccessValidationService                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. If user has employee role, automatically grant access                    │
│ 2. Otherwise, get validator for resource type from AccessValidatorRegistry  │
│ 3. Call validator's canAccess method to check if user has access            │
└───────────────────────────────────────────────────────────────────────────┬─┘
                                                                            │
                                                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AccessValidator                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Check if user is owner of resource                                       │
│ 2. Return true if user has access, false otherwise                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Class Diagram

The following diagram shows the main classes and interfaces in the Firefly Authorization Library and their relationships:

```
┌───────────────────────┐      ┌───────────────────────┐
│  AuthContextWebFilter │      │       AuthInfo        │
├───────────────────────┤      ├───────────────────────┤
│ - filter()            │      │ - partyId             │
│ - createAuthentication│      │ - employeeId          │
└───────────┬───────────┘      │ - serviceAccountId    │
            │                  │ - roles               │
            │ creates          │ - scopes              │
            ▼                  │ - requestId           │
┌───────────────────────┐      ├───────────────────────┤
│     AuthDetails       │      │ + getCurrent()        │
├───────────────────────┤      │ + isCustomer()        │
│ - requestId           │      │ + isEmployee()        │
│ - employeeId          │      │ + isServiceAccount()  │
│ - serviceAccountId    │      │ + isAdmin()           │
└───────────────────────┘      │ + isCustomerSupport() │
                               │ + isSupervisor()      │
                               │ + isManager()         │
                               │ + hasRole()           │
                               │ + hasAnyRole()        │
                               │ + hasAllRoles()       │
                               │ + hasScope()          │
                               │ + hasAnyScope()       │
                               │ + hasAllScopes()      │
                               └───────────────────────┘
                                          ▲
                                          │
                                          │ uses
┌───────────────────────┐                 │
│  SecurityInterceptor  │◀────────────────┘
├───────────────────────┤
│ + checkRole()         │
│ + checkScope()        │
│ + checkOwnership()    │
│ + checkExpression()   │
│ + preAuthorize()      │
│                      │
└───────────┬───────────┘
            │
            │ uses
            ▼
┌───────────────────────┐      ┌───────────────────────┐
│AccessValidationService│      │AccessValidatorRegistry│
├───────────────────────┤      ├───────────────────────┤
│ + validateAccess()    │─────▶│ + getValidator()      │
└───────────────────────┘      │ + hasValidator()      │
                               └───────────┬───────────┘
                                           │
                                           │ manages
                                           ▼
                               ┌───────────────────────┐
                               │   «interface»         │
                               │   AccessValidator     │
                               ├───────────────────────┤
                               │ + getResourceName()   │
                               │ + canAccess()         │
                               └───────────────────────┘
                                           ▲
                                           │ implements
                                           │
                 ┌─────────────────────────┼─────────────────────────┐
                 │                         │                         │
    ┌────────────┴────────────┐ ┌──────────┴─────────────┐ ┌────────┴────────────┐
    │ContractAccessValidator  │ │AccountAccessValidator  │ │CustomAccessValidator│
    ├─────────────────────────┤ ├────────────────────────┤ ├─────────────────────┤
    │ + getResourceName()     │ │ + getResourceName()    │ │ + getResourceName() │
    │ + canAccess()           │ │ + canAccess()          │ │ + canAccess()       │
    └─────────────────────────┘ └────────────────────────┘ └─────────────────────┘


┌───────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
│     «annotation»      │      │     «annotation»      │      │     «annotation»      │
│     @Secured          │      │     @RequiresRole     │      │     @RequiresScope    │
├───────────────────────┤      ├───────────────────────┤      ├───────────────────────┤
│ + value()             │      │ + value()             │      │ + value()             │
└───────────────────────┘      │ + anyOf()             │      │ + anyOf()             │
                               └───────────────────────┘      └───────────────────────┘

┌────────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
│     «annotation»       │      │     «annotation»      │      │     «annotation»      │
│  @RequiresOwnership    │      │  @RequiresExpression  │      │     @PreAuthorize     │
├────────────────────────┤      ├───────────────────────┤      ├───────────────────────┤
│ + resource()           │      │ + value()             │      │ + value()             │
│ + paramIndex()         │      └───────────────────────┘      └───────────────────────┘
│ + paramName()          │
│ + accessType()         │      ┌───────────────────────┐
│ + bypassForBackoffice()│      │     «annotation»      │
└────────────────────────┘      │  @AccessValidatorFor  │
                                ├───────────────────────┤
                                │ + value()             │
                                └───────────────────────┘
```

## How It Works

### Authentication Process

The Firefly Authorization Library uses a header-based authentication approach, where the authentication is delegated to the perimeter (Istio/API Gateway). The perimeter injects authentication headers into the request, which are then processed by the library to create an Authentication object.

1. **Header Injection**: The API Gateway or Istio injects authentication headers into the request:
   - `X-Party-ID`: Identifier of the client (required for CUSTOMER role)
   - `X-Employee-ID`: Identifier of the employee (required for employee roles: ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF)
   - `X-Service-Account-ID`: Identifier of the service account (required for SERVICE_ACCOUNT role)
   - `X-Auth-Roles`: Roles of the subject, comma-separated
   - `X-Auth-Scopes`: OAuth2 scopes, comma-separated
   - `X-Request-ID`: For traceability

2. **Header Processing**: The `AuthContextWebFilter` processes these headers:
   - Determines the user type (Customer, Employee, Service Account) based on the roles
   - Validates that the required headers are present based on the user type
   - Builds a list of authorities from the roles and scopes
   - Creates an Authentication object with the appropriate principal and authorities
   - Stores the Authentication object in the ReactiveSecurityContextHolder

3. **Authentication Access**: The `AuthInfo` class provides a convenient way to access the current authentication information:
   - `AuthInfo.getCurrent()` returns a Mono that emits the current AuthInfo
   - The AuthInfo object provides methods to access the party ID, employee ID, service account ID, roles, and scopes
   - It also provides methods to check if the user has specific roles or scopes

### Authorization Process

The library provides a comprehensive set of annotations for securing methods with different access control rules. These annotations are processed by the `SecurityInterceptor`, which enforces the security rules.

1. **Method Annotation**: Methods that require authorization are annotated with one or more security annotations:
   - `@RequiresRole`: Requires the user to have a specific role
   - `@RequiresScope`: Requires the user to have a specific OAuth2 scope
   - `@RequiresOwnership`: Requires the user to be the owner of the resource
   - `@RequiresExpression`: Requires a custom SpEL expression to evaluate to true
   - `@PreAuthorize`: Similar to Spring Security's @PreAuthorize but works with reactive code

2. **Annotation Processing**: The `SecurityInterceptor` intercepts method calls to methods annotated with security annotations:
   - Gets the current AuthInfo from the ReactiveSecurityContextHolder
   - Checks if the user has the required role/scope
   - For ownership checks, extracts the resource ID from the method parameters
   - Calls the AccessValidationService to validate ownership
   - If all checks pass, proceeds with the method execution
   - Otherwise, throws an AccessDeniedException

### Resource Ownership Validation

The library provides a pluggable/extensible validation mechanism for checking if a user has access to a specific resource. This is particularly useful for ensuring that users can only access their own resources.

1. **Validator Registration**: Validators are registered at application startup:
   - Classes that implement the `AccessValidator` interface are discovered automatically
   - The `@AccessValidatorFor` annotation specifies the resource type that the validator is responsible for
   - The `AccessValidatorRegistry` manages the validators and provides a way to look them up by resource type

2. **Ownership Validation**: When a method annotated with `@RequiresOwnership` is called:
   - The `SecurityInterceptor` extracts the resource ID from the method parameters
   - It calls the `AccessValidationService` to validate ownership
   - The `AccessValidationService` gets the validator for the resource type from the `AccessValidatorRegistry`
   - It calls the validator's `canAccess` method to check if the user has access to the resource
   - If the user has any employee role and `bypassForBackoffice` is true, access is automatically granted
   - Otherwise, the validator checks if the user is the owner of the resource

## Features

### Header-Based Authentication

- **WebFilter (AuthContextWebFilter)**: Reads headers injected by Istio/API Gateway and builds an Authentication object.
  - `X-Party-ID`: Identifier of the client (required for CUSTOMER role).
  - `X-Employee-ID`: Identifier of the employee (required for employee roles: ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF).
  - `X-Service-Account-ID`: Identifier of the service account (required for SERVICE_ACCOUNT role).
  - `X-Auth-Roles`: Roles of the subject, comma-separated.
  - `X-Auth-Scopes`: OAuth2 scopes like contracts.read, accounts.write, comma-separated.
  - `X-Request-ID`: For traceability.

### Role-Based Access Control

- **Comprehensive Role System**: Support for a wide range of roles:
  - **Customer Roles**: `CUSTOMER`
  - **Employee Roles**: `ADMIN`, `CUSTOMER_SUPPORT`, `SUPERVISOR`, `MANAGER`, `BRANCH_STAFF`
  - **Service Roles**: `SERVICE_ACCOUNT`

- **AuthInfo**: Wrapper utility that exposes authentication data.
  - `getPartyId()`: Gets the party ID (for CUSTOMER role).
  - `getEmployeeId()`: Gets the employee ID (for employee roles).
  - `getServiceAccountId()`: Gets the service account ID (for SERVICE_ACCOUNT role).
  - `getRoles()`: Gets all roles.
  - `getScopes()`: Gets all scopes.
  - **Role Checking Methods**:
    - Basic: `isCustomer()`, `isEmployee()`, `isServiceAccount()`
    - Granular: `isAdmin()`, `isCustomerSupport()`, `isSupervisor()`, `isManager()`
    - Generic: `hasRole(role)`, `hasAnyRole(roles...)`, `hasAllRoles(roles...)`

- **Security Annotations**: A set of annotations for securing methods with different access control rules.
  - **@RequiresRole**: Requires the user to have a specific role.
  - **@RequiresScope**: Requires the user to have a specific OAuth2 scope.
  - **@RequiresOwnership**: Requires the user to be the owner of the resource.
  - **@RequiresExpression**: Requires a custom SpEL expression to evaluate to true.
  - **@PreAuthorize**: Similar to Spring Security's @PreAuthorize but works with reactive code.

- **SecurityInterceptor**: Intercepts methods annotated with security annotations and enforces security rules.
  - Supports different types of access control (role-based, scope-based, ownership-based, expression-based).
  - Supports method-level and class-level annotations.
  - Supports composition of access rules.
  - Automatically allows access for users with employee roles (configurable).

- **AccessValidationService**: Defines pluggable/extensible validation logic according to the resource type.
  - Supports validation for contracts and accounts.
  - Automatically allows access for users with employee roles.
  - For CUSTOMER role, validates that the user is the owner of the resource.
  - Extensible to support additional resource types through auto-discovery.

- **@AccessValidatorFor Annotation**: Marks classes that implement the AccessValidator interface.
  - Specifies the resource type that the validator is responsible for.
  - Used by the AccessValidatorRegistry to auto-discover and register validators.

- **AccessValidator Interface**: Defines the contract for validators that check access to resources.
  - `getResourceName()`: Gets the name of the resource type.
  - `canAccess(resourceId, authInfo)`: Validates if the user has access to the resource.

- **AccessValidatorRegistry**: Discovers and registers validators at application startup.
  - Automatically finds all beans that implement the AccessValidator interface.
  - Uses the @AccessValidatorFor annotation to determine the resource type.

## Requirements

- Java 21 or higher
- Spring Boot 3.x
- Spring WebFlux
- Spring Security

## Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.catalis</groupId>
    <artifactId>lib-common-auth</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Usage

### 1. Enable the library

The library is auto-configured when added as a dependency. No additional configuration is required.

### 2. Access the current authentication information

```java
import com.catalis.common.auth.model.AuthInfo;
import reactor.core.publisher.Mono;

public class MyService {

    public Mono<String> getCurrentUser() {
        return AuthInfo.getCurrent()
                .map(authInfo -> {
                    // Check for specific employee roles
                    if (authInfo.isAdmin()) {
                        return "Admin: " + authInfo.getEmployeeId();
                    } else if (authInfo.isCustomerSupport()) {
                        return "Customer Support: " + authInfo.getEmployeeId();
                    } else if (authInfo.isSupervisor()) {
                        return "Supervisor: " + authInfo.getEmployeeId();
                    } else if (authInfo.isManager()) {
                        return "Manager: " + authInfo.getEmployeeId();
                    } else if (authInfo.hasRole("BRANCH_STAFF")) {
                        return "Branch Staff: " + authInfo.getEmployeeId();
                    } else if (authInfo.isServiceAccount()) {
                        return "Service Account: " + authInfo.getServiceAccountId();
                    } else {
                        return "Customer: " + authInfo.getPartyId();
                    }
                });
    }

    public Mono<Boolean> canPerformAdminAction() {
        return AuthInfo.getCurrent()
                .map(authInfo -> authInfo.isAdmin() || authInfo.isManager());
    }

    public Mono<Boolean> canViewCustomerData() {
        return AuthInfo.getCurrent()
                .map(authInfo -> authInfo.isEmployee() || authInfo.hasRole("DATA_VIEWER"));
    }
}
```

### 3. Secure methods with annotations

#### Role-based access control

```java
import com.catalis.common.auth.annotation.RequiresRole;
import reactor.core.publisher.Mono;

public class AdminService {

    @RequiresRole("ADMIN")
    public Mono<List<User>> getAllUsers() {
        // This method will only be executed if the current user has the ADMIN role
        return userRepository.findAll().collectList();
    }

    @RequiresRole("ADMIN")
    public Mono<Void> deleteUser(String userId) {
        // This method will only be executed if the current user has the ADMIN role
        return userRepository.deleteById(userId);
    }

    @RequiresRole("CUSTOMER_SUPPORT")
    public Mono<User> viewUserDetails(String userId) {
        // This method will only be executed if the current user has the CUSTOMER_SUPPORT role
        return userRepository.findById(userId);
    }

    @RequiresRole(value = {"ADMIN", "MANAGER"}, anyOf = true)
    public Mono<Void> approveUserRequest(String requestId) {
        // This method will only be executed if the current user has either the ADMIN or MANAGER role
        return requestService.approve(requestId);
    }

    @RequiresRole(value = {"SUPERVISOR", "MANAGER"}, anyOf = false)
    public Mono<Void> performSensitiveOperation() {
        // This method will only be executed if the current user has both SUPERVISOR and MANAGER roles
        return sensitiveOperationService.execute();
    }
}
```

#### Scope-based access control

```java
import com.catalis.common.auth.annotation.RequiresScope;
import reactor.core.publisher.Mono;

public class ContractService {

    @RequiresScope("contracts.read")
    public Mono<Contract> getContractById(String contractId) {
        // This method will only be executed if the current user has the contracts.read scope
        return contractRepository.findById(contractId);
    }

    @RequiresScope("contracts.write")
    public Mono<Contract> updateContract(Contract contract) {
        // This method will only be executed if the current user has the contracts.write scope
        return contractRepository.save(contract);
    }
}
```

#### Ownership-based access control

```java
import com.catalis.common.auth.annotation.RequiresOwnership;
import reactor.core.publisher.Mono;

public class ContractService {

    @RequiresOwnership(resource = "contract", paramName = "contractId")
    public Mono<Contract> getContractById(String contractId) {
        // This method will only be executed if the current user is the owner of the contract
        // or has any employee role (bypassForBackoffice = true by default)
        return contractRepository.findById(contractId);
    }

    @RequiresOwnership(
        resource = "contract", 
        paramIndex = 0, 
        accessType = "write", 
        bypassForBackoffice = false
    )
    public Mono<Contract> updateContract(String contractId, Contract contract) {
        // This method will only be executed if the current user is the owner of the contract
        // Even users with employee roles will be subject to the ownership check
        return contractRepository.save(contract);
    }
}
```

#### Expression-based access control

```java
import com.catalis.common.auth.annotation.RequiresExpression;
import reactor.core.publisher.Mono;

public class ContractService {

    @RequiresExpression("#authInfo.isAdmin() || #authInfo.isManager() || #args[0].startsWith('user-')")
    public Mono<Contract> getContractById(String contractId) {
        // This method will only be executed if the current user has the ADMIN or MANAGER role
        // or if the contractId starts with 'user-'
        return contractRepository.findById(contractId);
    }

    @RequiresExpression("#authInfo.isCustomerSupport() && #authInfo.hasScope('contracts.read')")
    public Mono<List<Contract>> getCustomerContracts(String customerId) {
        // This method will only be executed if the current user has the CUSTOMER_SUPPORT role
        // and the contracts.read scope
        return contractRepository.findByCustomerId(customerId).collectList();
    }

    @RequiresExpression("#authInfo.isSupervisor() || (#authInfo.isCustomer() && #authInfo.getPartyId() == #args[0])")
    public Mono<Contract> updateContract(String customerId, Contract contract) {
        // This method will only be executed if the current user is a SUPERVISOR
        // or if the user is a CUSTOMER and the customerId matches their partyId
        return contractRepository.save(contract);
    }
}
```

#### Spring Security-style access control

```java
import com.catalis.common.auth.annotation.PreAuthorize;
import reactor.core.publisher.Mono;

public class ContractService {

    @PreAuthorize("hasRole('ADMIN') || hasRole('MANAGER') || hasScope('contracts.read')")
    public Mono<Contract> getContractById(String contractId) {
        // This method will only be executed if the current user has the ADMIN or MANAGER role
        // or the contracts.read scope
        return contractRepository.findById(contractId);
    }

    @PreAuthorize("hasRole('ADMIN') && hasScope('contracts.write')")
    public Mono<Contract> updateContract(Contract contract) {
        // This method will only be executed if the current user has both the ADMIN role
        // and the contracts.write scope
        return contractRepository.save(contract);
    }

    @PreAuthorize("hasRole('CUSTOMER_SUPPORT') || (hasRole('CUSTOMER') && #customerId == #authInfo.getPartyId())")
    public Mono<List<Contract>> getCustomerContracts(String customerId) {
        // This method will only be executed if the current user has the CUSTOMER_SUPPORT role
        // or if the user is a CUSTOMER and the customerId matches their partyId
        return contractRepository.findByCustomerId(customerId).collectList();
    }

    @PreAuthorize("(hasRole('SUPERVISOR') || hasRole('MANAGER')) && hasScope('contracts.approve')")
    public Mono<Contract> approveContract(String contractId) {
        // This method will only be executed if the current user has either the SUPERVISOR or MANAGER role
        // and the contracts.approve scope
        return contractRepository.findById(contractId)
                .flatMap(contract -> {
                    contract.setStatus("APPROVED");
                    return contractRepository.save(contract);
                });
    }
}
```

#### Resource ownership validation

```java
import reactor.core.publisher.Mono;

public class ContractService {

    @RequiresOwnership(resource = "contract", paramName = "contractId")
    public Mono<Contract> getContractById(String contractId) {
        // This method will only be executed if the current user has access to the contract
        return contractRepository.findById(contractId);
    }
}
```

### 4. Create custom validators

This section provides a comprehensive tutorial on how to create custom validators for resource-based access control and how they work with the security annotations.

#### Understanding Resource Ownership Validation

Resource ownership validation is a key aspect of the Firefly Authorization Library. It allows you to control access to resources based on whether the user is the owner of the resource or has the appropriate role to access it.

The library provides built-in validators for common resource types like contracts and accounts, but you can create custom validators for your own resource types.

#### How Validators Work with Annotations

The Firefly Authorization Library provides several security annotations that can be used to secure methods. These annotations interact with validators in different ways, and choosing the right annotation depends on your specific security requirements.

##### When to Use Each Annotation Type

Here's a guide to help you choose the right annotation for your needs:

1. **Resource Ownership Annotations** (`@RequiresOwnership`):
   - **Use when**: You need to restrict access to resources based on ownership (e.g., a user can only access their own data).
   - **Best for**: Entity-specific access control where ownership matters.
   - **Examples**: Customer accessing their own contracts, accounts, or payments.
   - **Comparison**: These annotations provide the most fine-grained access control but require custom validators for each resource type.

2. **Role and Scope Annotations** (`@RequiresRole` and `@RequiresScope`):
   - **Use when**: Access should be restricted based on user roles or OAuth2 scopes, regardless of resource ownership.
   - **Best for**: Functionality-based access control where certain features are only available to specific roles.
   - **Examples**: Administrative functions, reporting features, or API endpoints with specific OAuth2 scope requirements.
   - **Comparison**: Simpler than ownership-based annotations but less fine-grained; they don't require custom validators.

3. **Expression-Based Annotations** (`@RequiresExpression` and `@PreAuthorize`):
   - **Use when**: You need complex access control logic that combines multiple conditions.
   - **Best for**: Scenarios where access depends on a combination of roles, scopes, resource ownership, and other factors.
   - **Examples**: Access that depends on both user role and resource properties, or time-based access restrictions.
   - **Comparison**: Most flexible but potentially more complex to maintain; can leverage custom validators through helper functions.

##### Annotation Selection Guide

| If you need to... | Use this annotation | Why |
|-------------------|---------------------|-----|
| Restrict access to a user's own resources | `@RequiresOwnership` | Automatically validates ownership using custom validators |
| Restrict access based on user role | `@RequiresRole` | Simple role-based check without custom validators |
| Restrict access based on OAuth2 scope | `@RequiresScope` | Simple scope-based check without custom validators |
| Combine multiple access conditions | `@PreAuthorize` | Flexible expression language with built-in functions |
| Implement complex custom logic | `@RequiresExpression` | Full access to SpEL for custom authorization rules |

##### How Annotations Interact with Validators

###### Resource Ownership Annotations (`@RequiresOwnership`)

When you use `@RequiresOwnership` on a method, the following happens:

1. The method call is intercepted by the `SecurityInterceptor` or `AccessControlAspect`.
2. The interceptor extracts the resource type and resource ID from the annotation and method parameters.
3. It gets the current user's authentication information using `AuthInfo.getCurrent()`.
4. It calls the `AccessValidationService` to validate if the user has access to the resource.
5. The `AccessValidationService` gets the appropriate validator from the `AccessValidatorRegistry` based on the resource type.
6. It calls the validator's `canAccess` method to check if the user has access to the resource.
7. If the user has access, the method execution proceeds; otherwise, an `AccessDeniedException` is thrown.

###### Role and Scope Annotations (`@RequiresRole` and `@RequiresScope`)

When you use `@RequiresRole` or `@RequiresScope` on a method, the following happens:

1. The method call is intercepted by the `SecurityInterceptor`.
2. The interceptor extracts the required role or scope from the annotation.
3. It gets the current user's authentication information using `AuthInfo.getCurrent()`.
4. It checks if the user has the required role or scope.
5. If the user has the required role or scope, the method execution proceeds; otherwise, an `AccessDeniedException` is thrown.

These annotations don't interact with validators directly, as they only check the user's roles or scopes.

###### Expression-Based Annotations (`@RequiresExpression` and `@PreAuthorize`)

When you use `@RequiresExpression` or `@PreAuthorize` on a method, the following happens:

1. The method call is intercepted by the `SecurityInterceptor`.
2. The interceptor extracts the expression from the annotation.
3. It gets the current user's authentication information using `AuthInfo.getCurrent()`.
4. It evaluates the expression using Spring's Expression Language (SpEL).
5. If the expression evaluates to `true`, the method execution proceeds; otherwise, an `AccessDeniedException` is thrown.

These annotations don't interact with validators directly, but they can include calls to functions that check resource ownership. For example, the `@PreAuthorize` annotation can include expressions like `isOwner('payment', #paymentId)`, which internally uses the same validation mechanism as `@RequiresOwnership`.

Note that the `isOwner` function used in the `@PreAuthorize` expression internally uses the same validation mechanism as `@RequiresOwnership`, calling the appropriate validator for the specified resource type.

##### Best Practices for Using Annotations with Validators

1. **Choose the simplest annotation that meets your needs**:
   - Use `@RequiresRole` or `@RequiresScope` when simple role/scope checks are sufficient.
   - Use `@RequiresOwnership` when ownership validation is needed.
   - Use `@PreAuthorize` or `@RequiresExpression` only for complex scenarios.

2. **Layer annotations for defense in depth**:
   - Apply role-based annotations at the class level.
   - Apply more specific ownership or expression-based annotations at the method level.

3. **Be consistent with resource types**:
   - Use the same resource type names across annotations and validators.
   - Document resource types clearly for team reference.

4. **Consider performance implications**:
   - Ownership validation often requires database queries, which can impact performance.
   - Cache validation results when appropriate.
   - Use `bypassForBackoffice=true` (default) with `@RequiresOwnership` to skip unnecessary validation for employee roles.

5. **Combine annotations with validators effectively**:
   - Create custom validators for all resource types that need ownership validation.
   - Ensure validators implement proper error handling and logging.
   - Test validators thoroughly with different user roles and scenarios.

#### Step-by-Step Guide to Creating a Custom Validator

Here's a step-by-step guide to creating a custom validator for a new resource type:

1. **Create a new class that implements the `AccessValidator` interface**:

```java
import com.catalis.common.auth.annotation.AccessValidatorFor;
import com.catalis.common.auth.model.AuthInfo;
import com.catalis.common.auth.service.AccessValidator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@AccessValidatorFor("payment")
public class PaymentAccessValidator implements AccessValidator {

    // Step 1: Add necessary dependencies
    private final PaymentRepository paymentRepository;

    public PaymentAccessValidator(PaymentRepository paymentRepository) {
        this.paymentRepository = paymentRepository;
    }

    // Step 2: Implement getResourceName method
    @Override
    public String getResourceName() {
        return "payment";
    }

    // Step 3: Implement canAccess method
    @Override
    public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
        // Step 4: Implement access control logic
        // Role-based access control with different permissions based on role
        if (authInfo.isAdmin() || authInfo.isManager()) {
            // Admins and managers have full access to all payments
            return Mono.just(true);
        }

        if (authInfo.isSupervisor()) {
            // Supervisors can access payments in their department
            return paymentRepository.findById(resourceId)
                .map(payment -> payment.getDepartment().equals(getDepartmentFromEmployeeId(authInfo.getEmployeeId())))
                .defaultIfEmpty(false);
        }

        if (authInfo.isCustomerSupport()) {
            // Customer support can only access non-sensitive payments
            return paymentRepository.findById(resourceId)
                .map(payment -> !payment.isSensitive())
                .defaultIfEmpty(false);
        }

        if (authInfo.isCustomer()) {
            // Customers can only access their own payments
            return paymentRepository.findById(resourceId)
                .map(payment -> payment.getCustomerId().equals(authInfo.getPartyId()))
                .defaultIfEmpty(false);
        }

        // Default deny access
        return Mono.just(false);
    }

    private String getDepartmentFromEmployeeId(String employeeId) {
        // In a real implementation, this would extract the department code from the employee ID
        // For simplicity, we'll just return the first 3 characters
        return employeeId.substring(0, 3);
    }
}
```

Let's break down the steps:

1. **Create a class that implements the `AccessValidator` interface**: Your validator class must implement this interface, which defines the contract for validators.

2. **Annotate the class with `@Component` and `@AccessValidatorFor`**:
   - `@Component`: Makes the class a Spring bean, so it can be discovered and managed by Spring.
   - `@AccessValidatorFor("payment")`: Specifies that this validator is responsible for the "payment" resource type. This annotation is used by the `AccessValidatorRegistry` to register the validator for the specified resource type.

3. **Implement the `getResourceName()` method**: This method should return the name of the resource type that the validator is responsible for. It's used as a fallback if the `@AccessValidatorFor` annotation is not present.

4. **Implement the `canAccess(String resourceId, AuthInfo authInfo)` method**: This is where you implement the access control logic. The method should return a `Mono<Boolean>` that emits `true` if the user has access to the resource, `false` otherwise.

5. **Add any necessary dependencies**: If your validator needs to access a database or other services to validate access, inject them as dependencies.

#### Using Your Custom Validator

Once you've created your custom validator, you can use it with the `@RequiresOwnership` annotation:

```java
@RequiresOwnership(resource = "payment", paramName = "paymentId")
public Mono<Payment> getPaymentById(String paymentId) {
    return paymentRepository.findById(paymentId);
}
```

Or with the `@PreAuthorize` annotation:

```java
@PreAuthorize("isOwner('payment', #paymentId)")
public Mono<Payment> getPaymentById(String paymentId) {
    return paymentRepository.findById(paymentId);
}
```

Note that the `isOwner` function used in the `@PreAuthorize` expression internally uses the same validation mechanism as `@RequiresOwnership`, calling the appropriate validator for the specified resource type.

#### Best Practices for Implementing Custom Validators

1. **Keep validators focused on a single resource type**: Each validator should be responsible for a single resource type. This makes the code more maintainable and easier to understand.

2. **Use dependency injection for repositories and services**: If your validator needs to access a database or other services, inject them as dependencies rather than creating them directly.

3. **Handle edge cases gracefully**: Make sure your validator handles edge cases like null values, missing resources, or invalid IDs. Use `defaultIfEmpty(false)` to handle cases where the resource doesn't exist.

4. **Consider caching for performance**: If validation involves expensive operations like database queries, consider caching the results to improve performance.

5. **Log validation decisions**: Use logging to track validation decisions, especially denials, to help with debugging and auditing.

6. **Use reactive programming patterns**: Since the library is built on WebFlux, use reactive programming patterns in your validators. Avoid blocking operations and use reactive repositories and services.

7. **Test your validators thoroughly**: Write unit tests for your validators to ensure they work correctly in all scenarios.

#### Advanced Example: Validator with Complex Logic

Here's a more advanced example of a validator that uses a repository to look up information and applies complex access rules:

```java
@Component
@AccessValidatorFor("order")
public class OrderAccessValidator implements AccessValidator {

    private final OrderRepository orderRepository;
    private final OrderItemRepository orderItemRepository;

    public OrderAccessValidator(OrderRepository orderRepository, OrderItemRepository orderItemRepository) {
        this.orderRepository = orderRepository;
        this.orderItemRepository = orderItemRepository;
    }

    @Override
    public String getResourceName() {
        return "order";
    }

    @Override
    public Mono<Boolean> canAccess(String orderId, AuthInfo authInfo) {
        // Employee roles have different access levels
        if (authInfo.isAdmin() || authInfo.isManager()) {
            // Admins and managers have full access
            return Mono.just(true);
        }

        if (authInfo.isSupervisor()) {
            // Supervisors can access orders in their region
            return orderRepository.findById(orderId)
                .flatMap(order -> {
                    String region = order.getRegion();
                    String supervisorRegion = getSupervisorRegion(authInfo.getEmployeeId());
                    return Mono.just(region.equals(supervisorRegion));
                })
                .defaultIfEmpty(false);
        }

        if (authInfo.isCustomerSupport()) {
            // Customer support can access non-premium orders
            return orderRepository.findById(orderId)
                .flatMap(order -> {
                    if (order.isPremium()) {
                        // For premium orders, check if the support agent is assigned to the customer
                        return Mono.just(order.getAssignedSupportId().equals(authInfo.getEmployeeId()));
                    } else {
                        // Non-premium orders are accessible to all support agents
                        return Mono.just(true);
                    }
                })
                .defaultIfEmpty(false);
        }

        // Customers can only access their own orders
        if (authInfo.isCustomer()) {
            return orderRepository.findById(orderId)
                .map(order -> order.getCustomerId().equals(authInfo.getPartyId()))
                .defaultIfEmpty(false);
        }

        // Service accounts might have specific access rules
        if (authInfo.isServiceAccount()) {
            // Check if the service account has the necessary scope
            if (authInfo.hasScope("orders.read")) {
                // Service accounts with orders.read scope can access all orders
                return Mono.just(true);
            }
            // Other service accounts might have limited access
            return Mono.just(false);
        }

        // Default deny access
        return Mono.just(false);
    }

    private String getSupervisorRegion(String employeeId) {
        // In a real implementation, this would look up the supervisor's region
        // For simplicity, we'll just return a hardcoded value
        return "NORTH";
    }
}
```

This example demonstrates:

1. **Multiple dependencies**: The validator injects multiple repositories to access different types of data.
2. **Complex access rules**: Different roles have different access rules, and some rules depend on properties of the resource.
3. **Nested queries**: The validator uses nested queries to check different conditions.
4. **Role-specific logic**: Each role has its own specific access logic.
5. **Service account handling**: The validator handles service accounts differently from user accounts.

#### Understanding the Validator Registration Process

When your application starts, the following happens:

1. The `AccessValidatorRegistry` is initialized as a Spring bean.
2. In its `@PostConstruct` method, it scans the application context for all beans that implement the `AccessValidator` interface.
3. For each validator bean, it gets the resource type from the `@AccessValidatorFor` annotation or the `getResourceName()` method.
4. It registers the validator in a map, with the resource type as the key and the validator as the value.
5. When the `AccessValidationService` needs to validate access to a resource, it gets the appropriate validator from the registry based on the resource type.

This auto-discovery mechanism means you don't need to manually register your validators; just make them Spring beans and annotate them with `@AccessValidatorFor`, and they'll be automatically discovered and registered.

#### Troubleshooting Common Issues

1. **Validator not found**: If you get an error saying "No validator found for resource type X", make sure:
   - Your validator class is annotated with `@Component` and `@AccessValidatorFor("X")`.
   - The resource type in the annotation matches the one you're using in the `@RequiresOwnership` annotation.
   - Your validator class is in a package that's scanned by Spring.

2. **Access denied unexpectedly**: If access is being denied when it should be granted, check:
   - Your validator's `canAccess` method is returning `true` for the appropriate conditions.
   - The resource ID being passed to the validator is correct.
   - The user has the expected roles and authorities.

3. **Validator not being called**: If your validator isn't being called at all, check:
   - The method is annotated with `@RequiresOwnership` with the correct resource type.
   - The aspect is being applied (check for AOP configuration issues).
   - The method is being called through a proxy (direct calls to methods within the same class bypass AOP).

By following this tutorial, you should be able to create custom validators for your own resource types and integrate them with the Firefly Authorization Library's annotation-based access control system.

## Migration Guide


#### After (using @PreAuthorize)

```java
@PreAuthorize("isOwner('contract', #contractId)")
public Mono<Contract> getContractById(String contractId) {
    return contractRepository.findById(contractId);
}
```

### Combining multiple security annotations

You can combine multiple security annotations to create more complex access control rules:

```java
@RequiresRole("CUSTOMER")
@RequiresScope("contracts.read")
@RequiresOwnership(resource = "contract", paramName = "contractId")
public Mono<Contract> getContractById(String contractId) {
    return contractRepository.findById(contractId);
}
```

This is equivalent to:

```java
@PreAuthorize("hasRole('CUSTOMER') && hasScope('contracts.read') && isOwner('contract', #contractId)")
public Mono<Contract> getContractById(String contractId) {
    return contractRepository.findById(contractId);
}
```

### Class-level annotations

You can also apply security annotations at the class level to secure all methods in the class:

```java
@RequiresRole("ADMIN")
public class AdminService {

    public Mono<List<User>> getAllUsers() {
        return userRepository.findAll().collectList();
    }

    public Mono<Void> deleteUser(String userId) {
        return userRepository.deleteById(userId);
    }
}
```

Method-level annotations take precedence over class-level annotations.

## Annotation Reference

This section provides a comprehensive reference for all annotations available in the Firefly Authorization Library.

### Security Annotations

#### @RequiresRole

**Purpose**: Requires the user to have a specific role.

**Parameters**:
- `value`: The role that the user must have (e.g., "CUSTOMER", "ADMIN", "CUSTOMER_SUPPORT", etc.)
- `anyOf`: Whether any of the specified roles is sufficient (default: true)

**Usage**:
```java
// Require a single role
@RequiresRole("ADMIN")
public Mono<List<User>> getAllUsers() {
    // Only users with ADMIN role can access this method
    return userRepository.findAll().collectList();
}

// Require any of multiple roles
@RequiresRole(value = {"ADMIN", "MANAGER"}, anyOf = true)
public Mono<Void> approveUserRequest(String requestId) {
    // Users with either ADMIN or MANAGER role can access this method
    return requestService.approve(requestId);
}

// Require all of multiple roles
@RequiresRole(value = {"SUPERVISOR", "MANAGER"}, anyOf = false)
public Mono<Void> performSensitiveOperation() {
    // Only users with both SUPERVISOR and MANAGER roles can access this method
    return sensitiveOperationService.execute();
}
```

**Best Practices**:
- Use on methods that should only be accessible to users with specific roles
- Can be applied at both method and class level
- When applied at class level, all methods in the class will require the specified role

#### @RequiresScope

**Purpose**: Requires the user to have a specific OAuth2 scope.

**Parameters**:
- `value`: The scope that the user must have (e.g., "contracts.read", "accounts.write")
- `anyOf`: Whether any of the specified scopes is sufficient (default: true)

**Usage**:
```java
// Require a single scope
@RequiresScope("contracts.read")
public Mono<Contract> getContractById(String contractId) {
    // Only users with contracts.read scope can access this method
    return contractRepository.findById(contractId);
}

// Require any of multiple scopes
@RequiresScope(value = {"contracts.read", "contracts.admin"}, anyOf = true)
public Mono<Contract> getContractById(String contractId) {
    // Users with either contracts.read or contracts.admin scope can access this method
    return contractRepository.findById(contractId);
}

// Require all of multiple scopes
@RequiresScope(value = {"contracts.read", "user.read"}, anyOf = false)
public Mono<Contract> getContractWithUserDetails(String contractId) {
    // Only users with both contracts.read and user.read scopes can access this method
    return contractRepository.findById(contractId);
}
```

**Best Practices**:
- Use on methods that should only be accessible to users with specific OAuth2 scopes
- Can be applied at both method and class level
- When applied at class level, all methods in the class will require the specified scope

#### @RequiresOwnership

**Purpose**: Requires the user to be the owner of the resource.

**Parameters**:
- `resource`: The type of resource being accessed (e.g., "contract", "account")
- `paramIndex`: The index of the parameter that contains the resource ID (default: 0)
- `paramName`: The name of the parameter that contains the resource ID (alternative to paramIndex)
- `accessType`: The access type required (e.g., "read", "write", "delete") (default: "read")
- `bypassForBackoffice`: Whether to bypass the check for users with employee roles (default: true)

**Usage**:
```java
// Basic usage with parameter index
@RequiresOwnership(resource = "contract", paramIndex = 0)
public Mono<Contract> getContractById(String contractId) {
    // Only the owner of the contract or employees can access this method
    return contractRepository.findById(contractId);
}

// Using parameter name instead of index
@RequiresOwnership(resource = "contract", paramName = "contractId")
public Mono<Contract> getContractById(String contractId) {
    // Only the owner of the contract or employees can access this method
    return contractRepository.findById(contractId);
}

// Specifying access type and disabling bypass for employees
@RequiresOwnership(
    resource = "contract", 
    paramName = "contractId", 
    accessType = "write", 
    bypassForBackoffice = false
)
public Mono<Contract> updateContract(String contractId, Contract contract) {
    // Only the owner of the contract can access this method, even employees must be owners
    return contractRepository.save(contract);
}
```

**Best Practices**:
- Use on methods that should only be accessible to the owner of the resource
- Prefer `paramName` over `paramIndex` for better readability and maintainability
- Set `bypassForBackoffice` to false for highly sensitive operations
- Use `accessType` to differentiate between read and write operations

#### @RequiresExpression

**Purpose**: Requires a custom SpEL expression to evaluate to true.

**Parameters**:
- `value`: The SpEL expression to evaluate

**Usage**:
```java
// Using authInfo properties
@RequiresExpression("#authInfo.isAdmin() || #authInfo.isManager()")
public Mono<List<User>> getAllUsers() {
    // Only users with ADMIN or MANAGER role can access this method
    return userRepository.findAll().collectList();
}

// Using method arguments
@RequiresExpression("#authInfo.isAdmin() || #args[0].startsWith('user-')")
public Mono<User> getUserById(String userId) {
    // Admins can access any user, others can only access users with IDs starting with 'user-'
    return userRepository.findById(userId);
}

// Complex conditions
@RequiresExpression("#authInfo.isCustomerSupport() && #authInfo.hasScope('contracts.read')")
public Mono<List<Contract>> getCustomerContracts(String customerId) {
    // Only customer support with contracts.read scope can access this method
    return contractRepository.findByCustomerId(customerId).collectList();
}
```

**Best Practices**:
- Use for complex authorization rules that can't be expressed with other annotations
- Keep expressions simple and readable
- Avoid complex business logic in expressions
- Can be applied at both method and class level

#### @PreAuthorize

**Purpose**: Similar to Spring Security's @PreAuthorize but works with reactive code.

**Parameters**:
- `value`: The SpEL expression to evaluate

**Usage**:
```java
// Basic role check
@PreAuthorize("hasRole('ADMIN')")
public Mono<List<User>> getAllUsers() {
    // Only users with ADMIN role can access this method
    return userRepository.findAll().collectList();
}

// Combining multiple conditions
@PreAuthorize("hasRole('ADMIN') || hasRole('MANAGER') || hasScope('contracts.read')")
public Mono<Contract> getContractById(String contractId) {
    // Users with ADMIN or MANAGER role, or contracts.read scope can access this method
    return contractRepository.findById(contractId);
}

// Using method arguments
@PreAuthorize("hasRole('CUSTOMER_SUPPORT') || (hasRole('CUSTOMER') && #customerId == #authInfo.getPartyId())")
public Mono<List<Contract>> getCustomerContracts(String customerId) {
    // Customer support can access any customer's contracts, customers can only access their own
    return contractRepository.findByCustomerId(customerId).collectList();
}

// Ownership check
@PreAuthorize("isOwner('contract', #contractId)")
public Mono<Contract> getContractById(String contractId) {
    // Only the owner of the contract or employees can access this method
    return contractRepository.findById(contractId);
}
```

**Best Practices**:
- Use for complex authorization rules that can be expressed with Spring Security's expression language
- Prefer over @RequiresExpression when using standard security functions
- Can be applied at both method and class level
- Use the built-in functions: hasRole, hasAnyRole, hasScope, hasAnyScope, isOwner


### Validator Annotations

#### @AccessValidatorFor

**Purpose**: Marks classes that implement the AccessValidator interface and specifies the resource type they validate.

**Parameters**:
- `value`: The type of resource that this validator is responsible for (e.g., "contract", "account")

**Usage**:
```java
@Component
@AccessValidatorFor("payment")
public class PaymentAccessValidator implements AccessValidator {

    @Override
    public String getResourceName() {
        return "payment";
    }

    @Override
    public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
        // Implement access control logic
        return paymentRepository.findById(resourceId)
            .map(payment -> payment.getCustomerId().equals(authInfo.getPartyId()))
            .defaultIfEmpty(false);
    }
}
```

**Best Practices**:
- Always implement the getResourceName method to return the same value as the annotation
- Use for creating custom validators for specific resource types
- Register as a Spring bean with @Component to enable auto-discovery

### Meta Annotations

#### @Secured

**Purpose**: Meta-annotation that marks other annotations as security annotations.

**Parameters**:
- `value`: The type of security check to perform

**Usage**:
```java
// Example of how to create a custom security annotation
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Secured("customCheck")
public @interface RequiresCustomCheck {
    String value();
}

// You would then need to implement the logic in SecurityInterceptor
```

**Best Practices**:
- Not intended for direct use in application code
- Used internally to mark security annotations
- Can be used to create custom security annotations

## Advanced Usage

### Real-World Examples

Here are some real-world examples of how to use the Firefly Authorization Library in different scenarios:

#### Banking Application Example

```java
@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    // Only customers can view their own accounts
    @GetMapping("/{accountId}")
    @RequiresOwnership(resource = "account", paramName = "accountId")
    public Mono<AccountDTO> getAccount(@PathVariable String accountId) {
        return accountService.getAccountById(accountId);
    }

    // Only admins can view all accounts
    @GetMapping
    @RequiresRole("ADMIN")
    public Flux<AccountDTO> getAllAccounts() {
        return accountService.getAllAccounts();
    }

    // Customer support can view accounts but not modify them
    @GetMapping("/customer/{customerId}")
    @RequiresRole("CUSTOMER_SUPPORT")
    public Flux<AccountDTO> getAccountsByCustomerId(@PathVariable String customerId) {
        return accountService.getAccountsByCustomerId(customerId);
    }

    // Supervisors can approve transactions
    @PostMapping("/{accountId}/transactions/{transactionId}/approve")
    @RequiresRole(value = {"SUPERVISOR", "MANAGER"}, anyOf = true)
    @RequiresScope("transactions.approve")
    public Mono<TransactionDTO> approveTransaction(
            @PathVariable String accountId,
            @PathVariable String transactionId) {
        return accountService.approveTransaction(accountId, transactionId);
    }

    // Branch staff can create accounts for customers
    @PostMapping
    @RequiresRole("BRANCH_STAFF")
    @RequiresScope("accounts.create")
    public Mono<AccountDTO> createAccount(@RequestBody AccountCreationRequest request) {
        return accountService.createAccount(request);
    }

    // Complex authorization rule using SpEL expression
    @PutMapping("/{accountId}/status")
    @RequiresExpression("""
        #authInfo.isAdmin() || 
        (#authInfo.isManager() && #args[1].getStatus() != 'CLOSED') || 
        (#authInfo.isSupervisor() && #args[1].getStatus() == 'ACTIVE')
    """)
    public Mono<AccountDTO> updateAccountStatus(
            @PathVariable String accountId,
            @RequestBody AccountStatusUpdateRequest request) {
        return accountService.updateAccountStatus(accountId, request.getStatus());
    }
}
```

#### E-Commerce Application Example

```java
@Service
public class OrderService {

    private final OrderRepository orderRepository;
    private final ProductRepository productRepository;

    public OrderService(OrderRepository orderRepository, ProductRepository productRepository) {
        this.orderRepository = orderRepository;
        this.productRepository = productRepository;
    }

    // Customers can only view their own orders
    @RequiresOwnership(resource = "order", paramName = "orderId")
    public Mono<OrderDTO> getOrderById(String orderId) {
        return orderRepository.findById(orderId)
                .map(this::mapToDTO);
    }

    // Customer support can view any order
    @RequiresRole("CUSTOMER_SUPPORT")
    public Flux<OrderDTO> getOrdersByCustomerId(String customerId) {
        return orderRepository.findByCustomerId(customerId)
                .map(this::mapToDTO);
    }

    // Only managers can cancel orders after they've been shipped
    @RequiresExpression("""
        #authInfo.isManager() || 
        (#authInfo.isCustomerSupport() && #args[1].getStatus() != 'SHIPPED') ||
        (#authInfo.isCustomer() && #authInfo.getPartyId() == #args[0].getCustomerId() && #args[1].getStatus() == 'PENDING')
    """)
    public Mono<OrderDTO> updateOrderStatus(Order order, OrderStatus newStatus) {
        order.setStatus(newStatus);
        return orderRepository.save(order)
                .map(this::mapToDTO);
    }

    // Only admins can view sales reports
    @RequiresRole("ADMIN")
    @RequiresScope("reports.sales")
    public Mono<SalesReportDTO> generateSalesReport(LocalDate startDate, LocalDate endDate) {
        return orderRepository.findByOrderDateBetween(startDate, endDate)
                .collectList()
                .map(this::generateReport);
    }

    private OrderDTO mapToDTO(Order order) {
        // Mapping logic
        return new OrderDTO();
    }

    private SalesReportDTO generateReport(List<Order> orders) {
        // Report generation logic
        return new SalesReportDTO();
    }
}
```

### Combining Multiple Security Annotations

You can combine multiple security annotations to create more complex access control rules. For example, you might want to require a user to have a specific role AND a specific scope AND be the owner of a resource:

```java
@RequiresRole("CUSTOMER")
@RequiresScope("contracts.read")
@RequiresOwnership(resource = "contract", paramName = "contractId")
public Mono<Contract> getContractById(String contractId) {
    return contractRepository.findById(contractId);
}
```

This is equivalent to using the `@PreAuthorize` annotation with a complex expression:

```java
@PreAuthorize("hasRole('CUSTOMER') && hasScope('contracts.read') && isOwner('contract', #contractId)")
public Mono<Contract> getContractById(String contractId) {
    return contractRepository.findById(contractId);
}
```

### Using SpEL Expressions for Complex Rules

The `@RequiresExpression` and `@PreAuthorize` annotations support Spring Expression Language (SpEL) for complex authorization rules. Here are some examples using the granular role system:

```java
// Check if the user has any of the specified employee roles
@RequiresExpression("#authInfo.isAdmin() || #authInfo.isManager() || #authInfo.isSupervisor()")
public Mono<List<User>> getAllUsers() {
    return userRepository.findAll().collectList();
}

// Check if the user has all of the specified scopes and is a customer support agent
@RequiresExpression("#authInfo.isCustomerSupport() && #authInfo.hasAllScopes('users.read', 'users.write')")
public Mono<User> updateUser(User user) {
    return userRepository.save(user);
}

// Role-based access control with different permissions based on role
@RequiresExpression("""
    #authInfo.isAdmin() || 
    (#authInfo.isManager() && #args[0].getDepartment() == 'IT') || 
    (#authInfo.isSupervisor() && #args[0].getTeam() == #authInfo.getEmployeeId().substring(0, 3)) ||
    (#authInfo.isCustomerSupport() && #args[0].getStatus() == 'OPEN')
""")
public Mono<Ticket> updateTicket(Ticket ticket) {
    return ticketRepository.save(ticket);
}

// Complex condition with method arguments and role-specific logic
@RequiresExpression("""
    #authInfo.isAdmin() || 
    (#authInfo.isCustomerSupport() && #args[0].startsWith('CS-')) || 
    (#authInfo.isCustomer() && #authInfo.getPartyId().equals(#args[0].substring(5)))
""")
public Mono<User> getUserById(String userId) {
    return userRepository.findById(userId);
}
```

### Securing Reactive Streams (Flux)

The security annotations work with both `Mono` and `Flux` return types:

```java
@RequiresRole("ADMIN")
public Flux<User> getAllUsers() {
    return userRepository.findAll();
}

@RequiresOwnership(resource = "account", paramName = "accountId")
public Flux<Transaction> getTransactionsByAccountId(String accountId) {
    return transactionRepository.findByAccountId(accountId);
}
```

### Custom Validators for Complex Ownership Rules

For complex ownership validation that can't be handled by the built-in validators, you can create custom validators:

```java
@Component
@AccessValidatorFor("organization")
public class OrganizationAccessValidator implements AccessValidator {

    private final OrganizationRepository organizationRepository;
    private final UserOrganizationRepository userOrganizationRepository;

    public OrganizationAccessValidator(OrganizationRepository organizationRepository,
                                      UserOrganizationRepository userOrganizationRepository) {
        this.organizationRepository = organizationRepository;
        this.userOrganizationRepository = userOrganizationRepository;
    }

    @Override
    public String getResourceName() {
        return "organization";
    }

    @Override
    public Mono<Boolean> canAccess(String resourceId, AuthInfo authInfo) {
        // If the user has any employee role, they have access to all organizations
        if (authInfo.isEmployee()) {
            return Mono.just(true);
        }

        // Check if the user is a member of the organization
        return userOrganizationRepository.findByUserIdAndOrganizationId(authInfo.getPartyId(), resourceId)
                .map(userOrg -> userOrg.getRole().equals("ADMIN") || userOrg.getRole().equals("MEMBER"))
                .defaultIfEmpty(false);
    }
}
```

## OpenAPI Documentation

The Firefly Authorization library includes built-in support for OpenAPI documentation using SpringDoc. This makes it easy to document your API endpoints and the required authentication headers.

### Setup

The library automatically configures OpenAPI documentation when you add the SpringDoc dependency to your project:

```xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webflux-ui</artifactId>
    <version>2.1.0</version>
</dependency>
```

### Accessing the Documentation

Once your application is running, you can access the OpenAPI documentation at:

- Swagger UI: `http://your-server:port/swagger-ui.html`
- OpenAPI JSON: `http://your-server:port/v3/api-docs`
- OpenAPI YAML: `http://your-server:port/v3/api-docs.yaml`

### Authentication Headers

The OpenAPI documentation automatically includes all the authentication headers required by the Firefly Authorization library:

- `X-Party-ID`: Identifier of the client (required for CUSTOMER role)
- `X-Employee-ID`: Identifier of the employee (required for employee roles: ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF)
- `X-Service-Account-ID`: Identifier of the service account (required for SERVICE_ACCOUNT role)
- `X-Auth-Roles`: Roles of the subject, comma-separated
- `X-Auth-Scopes`: OAuth2 scopes, comma-separated
- `X-Request-ID`: For traceability

These headers are included in all API endpoints documented by OpenAPI, making it clear to API consumers what headers are required for authentication.

### Customizing the Documentation

You can customize the OpenAPI documentation by creating your own `OpenAPIConfiguration` class that extends or replaces the default configuration:

```java
@Configuration
public class CustomOpenAPIConfiguration {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("My API")
                        .version("1.0.0")
                        .description("API documentation for my application")
                        .license(new License().name("Apache 2.0").url("https://www.apache.org/licenses/LICENSE-2.0")));
    }
}
```

## Performance Considerations and Best Practices

### Performance Optimization

1. **Use class-level annotations for common security rules**: If all methods in a class require the same security rules, use class-level annotations instead of method-level annotations to reduce boilerplate code.

2. **Avoid excessive validation**: The library automatically bypasses ownership validation for users with employee roles. Use this feature to avoid unnecessary database queries.

3. **Cache validation results**: For complex validation logic that involves database queries, consider caching the results to improve performance.

4. **Use the most specific annotation**: Choose the most specific annotation for your use case. For example, use `@RequiresRole` instead of `@RequiresExpression` if you only need to check roles.

### Security Best Practices

1. **Defense in depth**: Don't rely solely on the library for security. Implement additional security measures at the API Gateway and database levels.

2. **Principle of least privilege**: Assign the minimum necessary roles and scopes to users. Avoid giving administrative roles (like ADMIN) to users who don't need them.

3. **Audit logging**: Log all access control decisions, especially denials, for audit purposes. The library already logs these events, but consider adding additional logging for sensitive operations.

4. **Regular security reviews**: Regularly review your security annotations to ensure they are still appropriate for your application's security requirements.

5. **Test security rules**: Write tests that verify your security rules are working as expected. The library provides utilities for testing security annotations.

### Common Pitfalls

1. **Missing required headers**: Ensure that your API Gateway or Istio configuration correctly injects the required headers (X-Party-ID, X-Employee-ID, X-Service-Account-ID, X-Auth-Roles, X-Auth-Scopes).

2. **Incorrect parameter names**: When using `@RequiresOwnership`, ensure that the parameter name or index is correct. Incorrect parameter references will result in runtime errors.

3. **Complex SpEL expressions**: Avoid overly complex SpEL expressions in `@RequiresExpression` or `@PreAuthorize` annotations. Complex expressions are harder to test and maintain.

4. **Forgetting to handle access denied exceptions**: The library throws `AccessDeniedException` when access is denied. Ensure your application has appropriate exception handlers to convert these exceptions to appropriate HTTP responses.

## Troubleshooting

### Common Issues and Solutions

#### Missing Required Headers

**Issue**: The authentication fails because required headers are missing.

**Solution**: 
- Check your API Gateway or Istio configuration to ensure it correctly injects the required headers.
- For CUSTOMER users, ensure X-Party-ID is present.
- For employee roles (ADMIN, CUSTOMER_SUPPORT, SUPERVISOR, MANAGER, BRANCH_STAFF), ensure X-Employee-ID is present.
- For SERVICE_ACCOUNT users, ensure X-Service-Account-ID is present.
- For all users, ensure X-Auth-Roles is present with the appropriate role.

#### Access Denied Exceptions

**Issue**: Users are getting AccessDeniedException even though they should have access.

**Solution**:
- Check the logs to see why access was denied. The library logs access denial reasons.
- Verify that the user has the correct roles and scopes.
- If using ownership-based access control, verify that the user is the owner of the resource.
- If using expression-based access control, verify that the expression evaluates to true.

#### Parameter Not Found

**Issue**: When using @RequiresOwnership, you get an error saying the parameter was not found.

**Solution**:
- Ensure the parameter name or index specified in the annotation matches the method parameter.
- If using parameter names, ensure your code is compiled with the -parameters option to preserve parameter names.
- If using parameter index, ensure the index is correct (0-based).

#### SpEL Expression Evaluation Errors

**Issue**: SpEL expressions in @RequiresExpression or @PreAuthorize annotations are not evaluating as expected.

**Solution**:
- Verify the syntax of your SpEL expression.
- Check that the variables you're referencing (#authInfo, #args, etc.) are available in the context.
- Simplify complex expressions by breaking them down into smaller parts.
- Add debug logging to see the values of variables during expression evaluation.

#### Auto-Configuration Issues

**Issue**: The library's auto-configuration is not working as expected.

**Solution**:
- Ensure the library is correctly added as a dependency in your pom.xml or build.gradle.
- Check that Spring Boot's auto-configuration is enabled.
- Verify that you don't have conflicting configurations that might override the library's beans.
- Enable debug logging for Spring Boot auto-configuration to see what's happening.

### Debugging Tips

1. **Enable Debug Logging**: Add the following to your application.properties or application.yml to enable debug logging for the library:
   ```properties
   logging.level.com.catalis.common.auth=DEBUG
   ```

2. **Inspect Authentication**: Use `AuthInfo.getCurrent()` to inspect the current authentication information. For example:

   ```
   // In your service or controller
   AuthInfo.getCurrent().subscribe(authInfo -> {
       log.debug("Current authentication: {}", authInfo);
   });
   ```

3. **Test with Postman**: Use Postman to test your API with different headers to simulate different user types.

4. **Write Unit Tests**: Write unit tests for your security rules to verify they work as expected.

### Getting Help

If you're still having issues, consider:
- Checking the library's source code to understand how it works.
- Writing a minimal reproducible example to isolate the issue.
- Reaching out to the library maintainers for support.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
