# Bank Employee Roles

This document defines the roles for bank employees in the Firefly Authorization Library.

## Overview

The Firefly Authorization Library supports a comprehensive role-based access control system for bank employees. Instead of using a generic BACKOFFICE role, the library now uses fine-grained roles that better reflect the organizational structure and responsibilities within a bank.

## Employee Roles

### ADMIN

Administrators have full access to all resources and functionalities within the system. They are responsible for system configuration, user management, and other administrative tasks.

**Permissions:**
- Full access to all resources
- User management (create, update, delete users)
- Role assignment
- System configuration
- Audit log access
- Access to sensitive operations

### MANAGER

Managers have broad access to resources and can approve high-value transactions. They oversee the operations of specific departments or branches.

**Permissions:**
- Access to all customer accounts and contracts
- Approval of high-value transactions
- Access to department/branch performance metrics
- Staff management
- Limited administrative functions

### SUPERVISOR

Supervisors oversee the work of customer support representatives and branch staff. They have access to resources needed to resolve escalated issues.

**Permissions:**
- Access to customer accounts and contracts within their department
- Approval of medium-value transactions
- Handling of escalated customer issues
- Staff supervision
- Access to department performance metrics

### CUSTOMER_SUPPORT

Customer support representatives handle customer inquiries and basic transactions. They have limited access to customer data based on their support needs.

**Permissions:**
- View customer accounts and contracts (non-sensitive information)
- Process basic transactions
- Update customer information
- Create support tickets
- Limited access to sensitive operations

### BRANCH_STAFF

Branch staff work directly with customers in physical bank branches. They handle basic transactions and customer service.

**Permissions:**
- Process in-person transactions
- View customer accounts and contracts (non-sensitive information)
- Update basic customer information
- Limited access to sensitive operations

## Other Roles

### CUSTOMER

Customers are the end-users of the banking system. They have access only to their own accounts and contracts.

**Permissions:**
- View and manage their own accounts and contracts
- Perform transactions on their own accounts
- Update their personal information

### SERVICE_ACCOUNT

Service accounts are used for system-to-system communication. They have specific permissions based on their intended use.

**Permissions:**
- API access for specific operations
- Batch processing
- Reporting
- Integration with other systems

## Role Hierarchy

The roles follow a hierarchical structure, where higher-level roles generally have all the permissions of lower-level roles plus additional permissions:

1. ADMIN (highest level)
2. MANAGER
3. SUPERVISOR
4. CUSTOMER_SUPPORT / BRANCH_STAFF
5. CUSTOMER / SERVICE_ACCOUNT (specialized roles)

## Implementation

In the Firefly Authorization Library, these roles are used to determine:

1. Which headers are required for authentication (X-Employee-ID for employee roles, X-Party-ID for CUSTOMER role, X-Service-Account-ID for SERVICE_ACCOUNT role)
2. What resources a user can access
3. What operations a user can perform on those resources

The `AuthInfo.isEmployee()` method checks if a user has any of the employee roles (ADMIN, MANAGER, SUPERVISOR, CUSTOMER_SUPPORT, BRANCH_STAFF).

## Examples

### Access Control Based on Role

```java
if (authInfo.isAdmin()) {
    // Allow administrative operations
} else if (authInfo.isManager() || authInfo.isSupervisor()) {
    // Allow management operations
} else if (authInfo.isCustomerSupport() || authInfo.hasRole("BRANCH_STAFF")) {
    // Allow customer support operations
} else {
    // Deny access
}
```

### Resource Access

```java
// Check if user can access a specific account
if (authInfo.isEmployee()) {
    // Employees can access any account
    return true;
} else if (authInfo.isCustomer() && accountOwnerId.equals(authInfo.getPartyId())) {
    // Customers can only access their own accounts
    return true;
} else {
    // Deny access
    return false;
}
```