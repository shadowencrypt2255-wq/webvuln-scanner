"""AI Security Analyst endpoint (read-only, tool-bounded)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, DbSession, _context_for_org
from app.core import rbac
from app.models.assets import Project
from app.models.governance import AiSession
from app.schemas.misc import AiAnswer, AiQuery
from app.services import ai_analyst, audit

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/query", response_model=AiAnswer)
def ai_query(payload: AiQuery, user: CurrentUser, db: DbSession) -> AiAnswer:
    if payload.project_id is None:
        raise HTTPException(status_code=422, detail="project_id is required")
    project = db.get(Project, payload.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Not found")
    # Authorization: caller must belong to the project's org with AI_USE.
    ctx = _context_for_org(db, user, project.organization_id)
    ctx.require(rbac.AI_USE)

    answer = ai_analyst.answer_question(db, project.id, payload.question, user.id)

    db.add(AiSession(
        project_id=project.id, user_id=user.id, question=payload.question,
        answer=answer.answer, context_refs=answer.context_refs, provider=answer.provider,
    ))
    db.commit()
    audit.record(db, action="ai.query", actor_id=user.id,
                 organization_id=project.organization_id, resource_type="project",
                 resource_id=project.id, meta={"provider": answer.provider})
    return answer
