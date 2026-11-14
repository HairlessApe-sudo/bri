"""Tenant configuration API routes and trusted transaction scoping."""
from __future__ import annotations

from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Callable, Literal, NoReturn

import psycopg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from bri.access.policy import AccessGrant, Principal
from bri.access.roles import role_allows_permission
from bri.api.database import DatabaseUnavailable, TenantSession
from bri.privacy.models import DetectionCategory
from bri.privacy.postgres import (
    PostgresShieldConfigurationStore,
    PostgresSignatureConfigurationProvider,
    PostgresTenantSignatureStore,
)
from bri.privacy.regional import (
    ManagedTenantSignature,
    PrivacyShieldConfigurationManager,
    RegionalSignatureRegistry,
    ResolvedSignatureConfiguration,
    SignatureAuthorizationError,
    SignatureValidationError,
    TenantSignatureManager,
)
from bri.prompts.management import (
    PromptAuthorizationError,
    PromptManager,
    PromptNotFoundError,
    PromptValidationError,
    PromptVersion,
    PromptVersionConflict,
)
from bri.prompts.postgres import PostgresPromptRepository


@dataclass(frozen=True, slots=True)
class TrustedRequestContext:
    principal: Principal
    tenant_id: str
    effective_role: str
    permissions: frozenset[str]
    grants: tuple[AccessGrant, ...]
    auth_user_id: str | None
    session_id: str | None
    assurance_level: str
    assurance_methods: tuple[str, ...]
    identity_source: Literal["supabase", "synthetic"]
    synthetic_principal_id: str | None
    request_id: str


def build_trusted_request_context(
    principal: Principal,
    *,
    request_id: str,
    identity_source: Literal["supabase", "synthetic"],
    auth_user_id: str | None = None,
    session_id: str | None = None,
    assurance_level: str,
    assurance_methods: tuple[str, ...] = (),
) -> TrustedRequestContext:
    """Bind one server-resolved identity to its sole tenant and verified assurance."""
    if len(principal.tenant_ids) != 1:
        raise ValueError("single_tenant_context_required")
    tenant_id = next(iter(principal.tenant_ids))
    bindings = dict(principal.role_bindings)
    role = "platform_superadmin" if principal.platform_superadmin else bindings.get(tenant_id, "user")
    if role == "platform_superadmin" and not principal.platform_superadmin:
        role = "user"
    grants = tuple(
        grant for grant in principal.grants
        if (
            grant.tenant_id == tenant_id
            and role_allows_permission(role, grant.action)
        ) or (
            grant.tenant_id == "brs-platform"
            and principal.platform_superadmin
            and role_allows_permission("platform_superadmin", grant.action)
        )
    )
    effective_principal = replace(principal, grants=grants)
    permissions = frozenset(grant.action for grant in grants)
    if not request_id or not assurance_level:
        raise ValueError("trusted_request_context_incomplete")
    if identity_source == "supabase" and (not auth_user_id or not session_id or assurance_level != "aal2"):
        raise ValueError("verified_authentication_context_required")
    if identity_source == "synthetic" and (auth_user_id is not None or session_id is not None):
        raise ValueError("synthetic_identity_must_not_claim_remote_session")
    return TrustedRequestContext(
        principal=effective_principal,
        tenant_id=tenant_id,
        effective_role=role,
        permissions=permissions,
        grants=grants,
        auth_user_id=auth_user_id,
        session_id=session_id,
        assurance_level=assurance_level,
        assurance_methods=assurance_methods,
        identity_source=identity_source,
        synthetic_principal_id=principal.subject_id if identity_source == "synthetic" else None,
        request_id=request_id,
    )


ConnectionScope = Callable[[str | None], AbstractContextManager[psycopg.Connection]]
ConfigurationServicesFactory = Callable[[TrustedRequestContext, bool], "ConfigurationServices"]


@dataclass(frozen=True, slots=True)
class ConfigurationServices:
    prompts: PromptManager
    signatures: TenantSignatureManager
    privacy_configuration: PrivacyShieldConfigurationManager
    signature_provider: PostgresSignatureConfigurationProvider | Any


def tenant_connection_scope(database: Any, context: TrustedRequestContext, *, read_only: bool) -> ConnectionScope:
    """Create a repository scope pinned to the authorized request tenant/identity."""
    def open_scope(repository_tenant_id: str | None) -> AbstractContextManager[psycopg.Connection]:
        if repository_tenant_id != context.tenant_id:
            raise PermissionError("configuration_tenant_scope_mismatch")

        @contextmanager
        def scoped_connection():
            try:
                with database.configuration_context(
                    context.tenant_id,
                    auth_user_id=context.auth_user_id,
                    synthetic_principal_id=context.synthetic_principal_id,
                    read_only=read_only,
                ) as session:
                    if session.tenant_id != context.tenant_id or session.connection is None:
                        raise DatabaseUnavailable("configuration tenant scope unavailable")
                    yield session.connection
            except DatabaseUnavailable:
                raise
            except psycopg.Error as exc:
                raise DatabaseUnavailable("configuration database scope unavailable") from exc
        return scoped_connection()
    return open_scope


def build_postgres_configuration_services(
    database: Any, context: TrustedRequestContext, *, read_only: bool
) -> ConfigurationServices:
    scope = tenant_connection_scope(database, context, read_only=read_only)
    signature_store = PostgresTenantSignatureStore(scope)
    configuration_store = PostgresShieldConfigurationStore(scope)
    registry = RegionalSignatureRegistry.with_defaults()
    return ConfigurationServices(
        prompts=PromptManager(PostgresPromptRepository(scope)),
        signatures=TenantSignatureManager(signature_store),
        privacy_configuration=PrivacyShieldConfigurationManager(configuration_store),
        signature_provider=PostgresSignatureConfigurationProvider(scope, registry),
    )


class PromptVersionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=32_000)
    change_description: str = Field(min_length=1, max_length=512)
    expected_latest_version: int = Field(ge=0)


class PromptRestoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_latest_version: int = Field(ge=0)
    change_description: str | None = Field(default=None, min_length=1, max_length=512)


class TenantSignatureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature_id: str = Field(min_length=1, max_length=80)
    pattern: str = Field(min_length=1, max_length=128)
    case_sensitive: bool = False
    is_regex: bool = False
    active: bool = True

    def domain_value(self, signature_id: str | None = None) -> ManagedTenantSignature:
        return ManagedTenantSignature(
            signature_id=signature_id or self.signature_id,
            pattern=self.pattern,
            category=DetectionCategory.TENANT_SENSITIVE,
            case_sensitive=self.case_sensitive,
            is_regex=self.is_regex,
            active=self.active,
        )


class PromptVersionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str
    version: int
    version_id: str
    author_id: str
    created_at: datetime
    change_description: str
    previous_version_ref: str | None
    restored_from_version_id: str | None
    content_hash: str
    content: str


class TenantSignatureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature_id: str
    pattern: str
    category: str
    case_sensitive: bool
    is_regex: bool
    active: bool


def _prompt_response(value: PromptVersion) -> PromptVersionResponse:
    return PromptVersionResponse(
        tenant_id=value.tenant_id or "",
        version=value.version,
        version_id=value.version_id,
        author_id=value.author_id,
        created_at=value.created_at,
        change_description=value.change_description,
        previous_version_ref=value.previous_version_ref,
        restored_from_version_id=value.restored_from_version_id,
        content_hash=value.content_hash,
        content=value.content,
    )


def _signature_response(value: ManagedTenantSignature) -> TenantSignatureResponse:
    return TenantSignatureResponse(
        signature_id=value.signature_id,
        pattern=value.pattern,
        category=value.category.value,
        case_sensitive=value.case_sensitive,
        is_regex=value.is_regex,
        active=value.active,
    )


def _raise_safe_domain_error(exc: Exception) -> NoReturn:
    if isinstance(exc, (PromptAuthorizationError, SignatureAuthorizationError, PermissionError)):
        raise HTTPException(status_code=403, detail="Configuration permission denied") from None
    if isinstance(exc, (PromptVersionConflict,)) or (
        isinstance(exc, RuntimeError) and str(exc).endswith("_conflict")
    ):
        raise HTTPException(status_code=409, detail="Configuration changed; refresh and retry") from None
    if isinstance(exc, (PromptNotFoundError, LookupError)):
        raise HTTPException(status_code=404, detail="Configuration version not found") from None
    if isinstance(exc, (PromptValidationError, SignatureValidationError, ValueError)):
        raise HTTPException(status_code=422, detail="Invalid configuration request") from None
    if isinstance(exc, RuntimeError):
        raise HTTPException(status_code=503, detail="Configuration is unavailable") from None
    raise exc


def _require_configuration_write(context: TrustedRequestContext) -> None:
    if context.identity_source != "synthetic":
        raise HTTPException(
            status_code=403,
            detail="Configuration writes require the local development identity mechanism",
        )


def create_configuration_router(
    *,
    context_dependency: Callable[..., TrustedRequestContext],
    database: Any,
    services_factory: ConfigurationServicesFactory | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/configuration", tags=["configuration"])

    def services(context: TrustedRequestContext, *, write: bool) -> ConfigurationServices:
        if services_factory is not None:
            return services_factory(context, write)
        return build_postgres_configuration_services(database, context, read_only=not write)

    @router.get("/prompts/active", response_model=PromptVersionResponse)
    def active_tenant_prompt(context: TrustedRequestContext = Depends(context_dependency)) -> PromptVersionResponse:
        try:
            value = services(context, write=False).prompts.current_client(context.principal, context.tenant_id)
            return _prompt_response(value)
        except Exception as exc:
            _raise_safe_domain_error(exc)

    @router.get("/prompts/versions", response_model=list[PromptVersionResponse])
    def tenant_prompt_history(context: TrustedRequestContext = Depends(context_dependency)) -> list[PromptVersionResponse]:
        try:
            values = services(context, write=False).prompts.client_history(context.principal, context.tenant_id)
            return [_prompt_response(value) for value in values]
        except Exception as exc:
            _raise_safe_domain_error(exc)

    @router.post("/prompts/versions", response_model=PromptVersionResponse, status_code=201)
    def create_tenant_prompt(
        body: PromptVersionCreateRequest,
        context: TrustedRequestContext = Depends(context_dependency),
    ) -> PromptVersionResponse:
        _require_configuration_write(context)
        try:
            value = services(context, write=True).prompts.create_client_version(
                context.principal, context.tenant_id, body.content, body.change_description,
                expected_latest_version=body.expected_latest_version,
            )
            return _prompt_response(value)
        except Exception as exc:
            _raise_safe_domain_error(exc)

    @router.post("/prompts/versions/{version}/restore", response_model=PromptVersionResponse)
    def restore_tenant_prompt(
        version: int,
        body: PromptRestoreRequest,
        context: TrustedRequestContext = Depends(context_dependency),
    ) -> PromptVersionResponse:
        _require_configuration_write(context)
        try:
            value = services(context, write=True).prompts.restore_client_version(
                context.principal, context.tenant_id, version,
                expected_latest_version=body.expected_latest_version,
                change_description=body.change_description,
            )
            return _prompt_response(value)
        except Exception as exc:
            _raise_safe_domain_error(exc)

    @router.get("/privacy-signatures/active")
    def active_privacy_signature_configuration(
        context: TrustedRequestContext = Depends(context_dependency),
    ) -> dict[str, Any]:
        try:
            active = services(context, write=False)
            # Existing managers enforce exact tenant read permissions before the
            # provider returns one consistent config/signature/package snapshot.
            active.privacy_configuration.read(context.principal, context.tenant_id)
            active.signatures.read(context.principal, context.tenant_id)
            resolved: ResolvedSignatureConfiguration | None = active.signature_provider.load(context.tenant_id)
            if resolved is None:
                raise PromptNotFoundError("configuration_not_found")
            return {
                "tenant_id": context.tenant_id,
                "configuration_version": resolved.config.version,
                "primary_jurisdiction": resolved.config.primary_jurisdiction,
                "additional_regions": list(resolved.config.additional_regions),
                "package_versions": dict(resolved.effective.package_versions),
                "tenant_signature_version": resolved.effective.tenant_signature_version,
                "effective_configuration_version": resolved.effective.configuration_version,
                "signatures": [_signature_response(value).model_dump() for value in resolved.tenant_signatures],
            }
        except Exception as exc:
            _raise_safe_domain_error(exc)

    @router.post("/privacy-signatures", response_model=dict[str, Any], status_code=201)
    def create_tenant_signature(
        body: TenantSignatureRequest,
        context: TrustedRequestContext = Depends(context_dependency),
    ) -> dict[str, Any]:
        _require_configuration_write(context)
        try:
            revision = services(context, write=True).signatures.create(
                context.principal, context.tenant_id, body.domain_value()
            )
            return {
                "tenant_id": context.tenant_id,
                "version": revision.version,
                "signatures": [_signature_response(value).model_dump() for value in revision.signatures],
            }
        except Exception as exc:
            _raise_safe_domain_error(exc)

    @router.put("/privacy-signatures/{signature_id}", response_model=dict[str, Any])
    def update_tenant_signature(
        signature_id: str,
        body: TenantSignatureRequest,
        context: TrustedRequestContext = Depends(context_dependency),
    ) -> dict[str, Any]:
        _require_configuration_write(context)
        try:
            revision = services(context, write=True).signatures.update(
                context.principal, context.tenant_id, signature_id, body.domain_value(signature_id)
            )
            return {
                "tenant_id": context.tenant_id,
                "version": revision.version,
                "signatures": [_signature_response(value).model_dump() for value in revision.signatures],
            }
        except Exception as exc:
            _raise_safe_domain_error(exc)

    return router
