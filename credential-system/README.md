# CredentialStack - Blockchain Credential System

## Features

- Authorized issuer system
- Credential issuance with expiry
- Metadata storage (UTF-8)
- Credential validation and revocation
- Admin controls

## Contract Functions

### Read-Only Functions

- `get-credential`: Retrieves credential details
- `is-issuer`: Checks issuer authorization
- `is-credential-valid`: Verifies credential validity

### Public Functions

- `add-issuer`: Add authorized issuer
- `remove-issuer`: Remove issuer authorization
- `issue-credential`: Issue new credential
- `revoke-credential`: Revoke existing credential

## Error Codes

- `ERR-NOT-AUTHORIZED (u100)`: Unauthorized action
- `ERR-INVALID-ISSUER (u101)`: Invalid issuer
- `ERR-CREDENTIAL-EXISTS (u102)`: Duplicate credential
- `ERR-INVALID-CREDENTIAL (u103)`: Invalid credential
- `ERR-INVALID-PRINCIPAL (u104)`: Invalid principal
- `ERR-INVALID-EXPIRY (u105)`: Invalid expiry
- `ERR-INVALID-METADATA (u106)`: Invalid metadata

## Setup

```bash
# Install Clarinet
curl -sSL https://install.clarinet.sh | sh

# Clone repository
git clone https://github.com/yourusername/stx-credential-system.git
cd stx-credential-system

# Test contract
clarinet test
```

## Security Features

- Principal address validation
- Expiry date validation
- Metadata length checks
- Admin access control
- Issuer authorization