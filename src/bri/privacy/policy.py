"""Deterministic policy evaluation with a non-overridable platform floor."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence

from bri.privacy.models import (
    Detection,
    DetectionCategory,
    InputType,
    PolicyAction,
    ProcessingDestination,
    ProcessingPurpose,
    TenantSignature,
)


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
_RESTRICTIVENESS = {
    PolicyAction.ALLOW: 0,
    PolicyAction.MASK: 1,
    PolicyAction.BLOCK: 2,
}


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    category: DetectionCategory | None
    action: PolicyAction
    input_types: tuple[InputType, ...] = ()
    purposes: tuple[ProcessingPurpose, ...] = ()
    destinations: tuple[ProcessingDestination, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not _ID.fullmatch(self.rule_id):
            raise ValueError("invalid_policy")
        if self.category is not None and not isinstance(self.category, DetectionCategory):
            raise ValueError("invalid_policy")
        if not isinstance(self.action, PolicyAction):
            raise ValueError("invalid_policy")
        if not _enum_tuple(self.input_types, InputType):
            raise ValueError("invalid_policy")
        if not _enum_tuple(self.purposes, ProcessingPurpose):
            raise ValueError("invalid_policy")
        if not _enum_tuple(self.destinations, ProcessingDestination):
            raise ValueError("invalid_policy")


@dataclass(frozen=True, slots=True)
class TenantPolicy:
    tenant_id: str
    policy_id: str
    version: str
    rules: tuple[PolicyRule, ...]
    signatures: tuple[TenantSignature, ...] = ()
    sensitive_terms: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not _ID.fullmatch(self.tenant_id):
            raise ValueError("invalid_policy")
        if not isinstance(self.policy_id, str) or not _ID.fullmatch(self.policy_id):
            raise ValueError("invalid_policy")
        if not isinstance(self.version, str) or not _ID.fullmatch(self.version):
            raise ValueError("invalid_policy")
        if not isinstance(self.rules, tuple) or any(not isinstance(rule, PolicyRule) for rule in self.rules):
            raise ValueError("invalid_policy")
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("invalid_policy")
        if not isinstance(self.signatures, tuple) or any(
            not isinstance(signature, TenantSignature) for signature in self.signatures
        ):
            raise ValueError("invalid_policy")
        if len({signature.signature_id for signature in self.signatures}) != len(self.signatures):
            raise ValueError("invalid_policy")
        if not isinstance(self.sensitive_terms, tuple) or any(
            not isinstance(term, str)
            or not term
            or len(term) > 256
            or any(ord(char) < 32 for char in term)
            for term in self.sensitive_terms
        ):
            raise ValueError("invalid_policy")
        if len({term.casefold() for term in self.sensitive_terms}) != len(self.sensitive_terms):
            raise ValueError("invalid_policy")


@dataclass(frozen=True, slots=True)
class PlatformPolicy:
    policy_id: str
    version: str
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not _ID.fullmatch(self.policy_id):
            raise ValueError("invalid_platform_policy")
        if not isinstance(self.version, str) or not _ID.fullmatch(self.version):
            raise ValueError("invalid_platform_policy")
        if not isinstance(self.rules, tuple) or any(not isinstance(rule, PolicyRule) for rule in self.rules):
            raise ValueError("invalid_platform_policy")
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("invalid_platform_policy")
        if any(rule.action is PolicyAction.ALLOW for rule in self.rules):
            raise ValueError("invalid_platform_policy")


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    decision: PolicyAction
    actions: tuple[tuple[Detection, PolicyAction], ...]
    mask_all: bool
    matched_rule_ids: tuple[str, ...]
    failure_reason: str | None = None


class PolicyProvider(Protocol):
    def load(self, tenant_id: str) -> TenantPolicy | None:
        """Load the approved tenant policy; never substitute another tenant."""
        ...


class MappingPolicyProvider:
    """Explicit in-memory provider useful for tests and local composition only."""

    def __init__(self, policies: Mapping[str, TenantPolicy]) -> None:
        self._policies = dict(policies)

    def load(self, tenant_id: str) -> TenantPolicy | None:
        return self._policies.get(tenant_id)


class PolicyEngine:
    def __init__(self, platform_policy: PlatformPolicy) -> None:
        if not isinstance(platform_policy, PlatformPolicy):
            raise ValueError("invalid_platform_policy")
        try:
            platform_policy.__post_init__()
        except Exception:
            raise ValueError("invalid_platform_policy") from None
        self._platform_policy = platform_policy

    @property
    def platform_policy(self) -> PlatformPolicy:
        return self._platform_policy

    def evaluate(
        self,
        policy: TenantPolicy | None,
        detections: Sequence[Detection],
        *,
        tenant_id: str,
        input_type: InputType,
        purpose: ProcessingPurpose,
        destination: ProcessingDestination,
    ) -> PolicyEvaluation:
        if policy is None:
            return _blocked("policy_unavailable")
        if (
            not isinstance(policy, TenantPolicy)
            or policy.tenant_id != tenant_id
            or not _valid_policy(policy)
        ):
            return _blocked("invalid_policy")
        if not isinstance(input_type, InputType) or not isinstance(purpose, ProcessingPurpose):
            return _blocked("invalid_processing_context")
        if not isinstance(destination, ProcessingDestination):
            return _blocked("invalid_processing_context")
        if any(not isinstance(finding, Detection) for finding in detections):
            return _blocked("invalid_detection_result")

        matched_ids: set[str] = set()
        mask_all = False
        global_platform = self._matching(
            self._platform_policy.rules, None, input_type, purpose, destination
        )
        global_tenant = self._matching(policy.rules, None, input_type, purpose, destination)
        global_restrictions = global_platform + global_tenant
        if global_restrictions:
            global_action = max(
                (rule.action for rule in global_restrictions), key=_RESTRICTIVENESS.__getitem__
            )
            matched_ids.update(rule.rule_id for rule in global_restrictions)
            if global_action is PolicyAction.BLOCK:
                return PolicyEvaluation(
                    PolicyAction.BLOCK, (), False, tuple(sorted(matched_ids))
                )
            mask_all = global_action is PolicyAction.MASK

        actions: list[tuple[Detection, PolicyAction]] = []
        for finding in detections:
            if not isinstance(finding.category, DetectionCategory):
                return _blocked("invalid_detection_result")
            platform_rules = self._matching(
                self._platform_policy.rules, finding.category, input_type, purpose, destination
            )
            tenant_rules = self._matching(
                policy.rules, finding.category, input_type, purpose, destination
            )
            candidates = [rule.action for rule in platform_rules + tenant_rules]
            # Mandatory floor: every detected sensitive category is at least masked.
            candidates.append(PolicyAction.MASK)
            action = max(candidates, key=_RESTRICTIVENESS.__getitem__)
            actions.append((finding, action))
            matched_ids.update(
                rule.rule_id
                for rule in platform_rules + tenant_rules
                if _RESTRICTIVENESS[rule.action] >= _RESTRICTIVENESS[action]
            )

        if any(action is PolicyAction.BLOCK for _, action in actions):
            decision = PolicyAction.BLOCK
        elif mask_all or any(action is PolicyAction.MASK for _, action in actions):
            decision = PolicyAction.MASK
        else:
            decision = PolicyAction.ALLOW
        return PolicyEvaluation(
            decision,
            tuple(actions),
            mask_all,
            tuple(sorted(matched_ids)),
        )

    @staticmethod
    def _matching(
        rules: Sequence[PolicyRule],
        category: DetectionCategory | None,
        input_type: InputType,
        purpose: ProcessingPurpose,
        destination: ProcessingDestination,
    ) -> list[PolicyRule]:
        return [
            rule
            for rule in rules
            if rule.category is category
            and (not rule.input_types or input_type in rule.input_types)
            and (not rule.purposes or purpose in rule.purposes)
            and (not rule.destinations or destination in rule.destinations)
        ]


def _enum_tuple(value: object, enum_type: type[object]) -> bool:
    return isinstance(value, tuple) and all(isinstance(item, enum_type) for item in value)


def _valid_policy(policy: TenantPolicy) -> bool:
    try:
        policy.__post_init__()
    except Exception:
        return False
    return True


def _blocked(reason: str) -> PolicyEvaluation:
    return PolicyEvaluation(PolicyAction.BLOCK, (), False, (), reason)


DEFAULT_PLATFORM_POLICY = PlatformPolicy(
    policy_id="brs-privacy-baseline",
    version="1",
    rules=tuple(
        PolicyRule(
            rule_id=f"platform-mask-{category.value}",
            category=category,
            action=PolicyAction.MASK,
        )
        for category in DetectionCategory
    ),
)
