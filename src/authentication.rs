use anyhow::Ok;
/*
[Operational requirements]
According to the operational requirements described in Section 7 of:
https://www.ietf.org/archive/id/draft-ietf-mls-architecture-15.html#name-operational-requirements

The AS must provide methods for:
1. Issuing new credentials with a relevant credential lifetime,
2. Validating a credential against a reference identifier,
3. Validating whether or not two credentials represent the same client, and
4. Optionally revoking credentials which are no longer authorized.

Our sketched solution for an AS will cover 1, 2, and 3, but we omit 4 due to time constraints.

[Strucutre of the AS and Credentials]
The AS should be a standalone component, which when presented a credential, will validate
it and return a boolean value indicating whether the credential is valid or not.
Issuance of credentials shpould be handled pre-flight and is explained further in the
"Credential issuance" section.

Credentials are represented as a [`Credential`] struct (defined in openmls-0.6.0):
pub struct Credential {
    credential_type: CredentialType,
    serialized_credential_content: VLBytes,
}

We use X.509 Certificates to represent Credentials which implies that the `credential_type`
should be set to `CredentialType::X509`.
The `serialized_credential_content` field is a byte array containing the X.509 certificate.

To validate X.509 certificate, we define a set of valid root CAs, which can sign certificates.
The AS will check if the certificate is signed by one of the root CAs, and if so, it will
return true. Otherwise, it will return false.

We do not use intermediate CAs as of now. This is to both ease the implementation and to
make validation checks more efficient. Current drone swarm architectures will be managed by a
single entity (e.g. troop, company or battalion command), and we assume that such an entity
will be responsible for issuance and therefore also represent the root CA(s).
We wish however, to make the implementation scalable, such that intermediate CAs can be
added in the future. This can be done by valdiating the full certifcate chain and verify that
a root CA is present at the end of the chain.


[Credential issuance]

[Credential validation]
Our application maintains a list of "reference identifiers" for the members of a group,
and the credentials provide "presented identifiers".

A member of a group is authenticated by first validating that the member's credential
legitimately represents some presented identifiers, and then ensuring that the reference
identifiers for the member are authenticated by those presented identifiers.

A member's credential is said to be validated with the AS when the AS verifies that the
credential's presented identifiers are correctly associated with the `signature_key`
field in the member's `LeafNode`, and that those identifiers match the reference
identifiers for the member.

(From RFC 9420)
Whenever a new credential is introduced in the group, it MUST be validated with the AS.
This occurs at the following protocol events:
1. When a member receives a KeyPackage for use in an Add proposal.
2. When a member joins a group via a GroupInfo object (from Welcome or external Commit).
3. When a member receives an Add proposal.
4. When a member receives an Update proposal with a new credential.
5. When a Commit includes a new credential in the UpdatePath.
6. When an external_senders extension is added (not relevant here).
7. When an existing external_senders extension is updated (not relevant here).

In short, validation is required whenever group membership or state is modified.

(From OpenMLS)
Credentials should be checked:
1. When joining a group (by examining the ratchet tree).
2. When processing messages (looking at Add & Update proposals in a StagedCommit).

[Uniquely Identifying Clients]
To simplify our AS implementation, a node (drone) is represented by one unique credential.
Unlike messaging apps where a user may have multiple devices, we assume one credential
per drone, acting as a unique identifier.

When issuing credentials, the AS attests a signature key to a NODE_ID—an identifier unique
to each drone—used to validate presented identifiers.

[Credential Expiry and Revocation]
Not covered in our implementation.
*/
use openmls::prelude::*;

pub struct X509Credential {
    credential_type: CredentialType,
    serialized_credential_content: VLBytes,
}

impl X509Credential {
    pub fn new(serialized_credential_content: VLBytes) -> Self {
        let credential_type = CredentialType::X509;
        Self {
            credential_type,
            serialized_credential_content,
        }
    }

    pub fn validate(&self) -> bool {
        // Validate the X.509 certificate
        // This is a placeholder for the actual validation logic
        // In a real implementation, you would check the certificate against a list of trusted CAs
        true
    }

    pub fn from_der(der: &[u8]) -> Result<Self, openssl::error::ErrorStack> {
        // Placeholder for creating X509Credential from DER-encoded certificate.
        // Convert DER-encoded certificate to X509Credential
        let cert = openssl::x509::X509::from_der(der)?;
        let serialized_credential_content = cert.to_der()?;
        Ok(X509Credential::new(serialized_credential_content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::x509::X509;
    use std::fs;

    #[test]
    fn test_x509_credential() {
        // Load a sample X.509 certificate from a file
        let cert_data = fs::read("path/to/certificate.der").unwrap();
        let credential = X509Credential::from_der(&cert_data).unwrap();

        // Validate the credential
        assert!(credential.validate());
    }
}
