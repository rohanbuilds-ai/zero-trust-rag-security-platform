"""Authentication and identity resolution module for demonstration credentials.

NOTE: These synthetic Bearer tokens are strictly for local security demonstrations
and testing environments. Production deployments must integrate an enterprise OIDC/OAuth2
identity provider with cryptographically signed and verified JWTs.
"""

from typing import Dict, Optional
from zero_trust_rag.core.models import PrincipalContext, PrincipalRole, ClassificationLevel

# Demonstration tokens mapped to immutable server-side identities
DEMO_TOKEN_REGISTRY: Dict[str, PrincipalContext] = {
    # Default Tenant Users
    "demo-token-alice-reader": PrincipalContext(
        principal_id="user_alice",
        tenant_id="default_tenant",
        role=PrincipalRole.READER,
        clearance_level=ClassificationLevel.INTERNAL,
    ),
    "demo-token-bob-contrib": PrincipalContext(
        principal_id="user_bob",
        tenant_id="default_tenant",
        role=PrincipalRole.CONTRIBUTOR,
        clearance_level=ClassificationLevel.INTERNAL,
    ),
    "demo-token-charlie-admin": PrincipalContext(
        principal_id="user_charlie",
        tenant_id="default_tenant",
        role=PrincipalRole.TENANT_ADMIN,
        clearance_level=ClassificationLevel.CONFIDENTIAL,
    ),
    "demo-token-eve-low": PrincipalContext(
        principal_id="user_eve",
        tenant_id="default_tenant",
        role=PrincipalRole.READER,
        clearance_level=ClassificationLevel.PUBLIC,
    ),
    "demo-token-restricted-exec": PrincipalContext(
        principal_id="user_exec_dave",
        tenant_id="default_tenant",
        role=PrincipalRole.TENANT_ADMIN,
        clearance_level=ClassificationLevel.RESTRICTED,
    ),

    # Secondary Isolated Tenant Users (tenant_isolated_beta)
    "demo-token-tenant-beta-user": PrincipalContext(
        principal_id="user_beta_zara",
        tenant_id="tenant_isolated_beta",
        role=PrincipalRole.CONTRIBUTOR,
        clearance_level=ClassificationLevel.INTERNAL,
    ),
    "demo-token-tenant-beta-admin": PrincipalContext(
        principal_id="user_beta_boris",
        tenant_id="tenant_isolated_beta",
        role=PrincipalRole.TENANT_ADMIN,
        clearance_level=ClassificationLevel.CONFIDENTIAL,
    ),

    # Platform Administrator (explicit controlled capability)
    "demo-token-platform-admin": PrincipalContext(
        principal_id="user_platform_root",
        tenant_id="default_tenant",
        role=PrincipalRole.PLATFORM_ADMIN,
        clearance_level=ClassificationLevel.RESTRICTED,
    ),
}

def resolve_token(token: str) -> Optional[PrincipalContext]:
    """Resolve a Bearer token against the demonstration registry."""
    if not token or not isinstance(token, str):
        return None
    cleaned = token.strip()
    return DEMO_TOKEN_REGISTRY.get(cleaned)

def register_test_token(token: str, context: PrincipalContext) -> None:
    """Helper for dynamically registering a principal in unit/integration tests."""
    DEMO_TOKEN_REGISTRY[token] = context
