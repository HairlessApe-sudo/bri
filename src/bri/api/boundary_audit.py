"""One post-rollback denial writer shared by the two BRI HTTP boundaries."""
from fastapi import Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from bri.api.database import DatabaseUnavailable


def mark(request: Request, action: str, phase: str) -> None:
    request.state.audit_action = action
    request.state.audit_phase = phase


async def audit_denial(request: Request, response: Response, database) -> Response:
    action = getattr(request.state, "audit_action", None)
    if not action or response.status_code < 400:
        return response
    identity = getattr(request.state, "authenticated_identity", None)
    try:
        await run_in_threadpool(
            database.record_boundary_denial, action, request.state.audit_phase,
            "failure" if response.status_code >= 500 else "denied", request.state.request_id,
            identity.auth_user_id if identity else None, identity.issuer if identity else None,
        )
    except DatabaseUnavailable:
        return JSONResponse({"detail": "Security audit unavailable"}, status_code=503)
    return response
