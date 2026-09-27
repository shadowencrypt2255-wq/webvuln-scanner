"""Project CRUD within an organization."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import DbSession, OrgContext, ProjectDep
from app.core import rbac
from app.models.assets import Project
from app.schemas.assets import ProjectCreate, ProjectOut, ProjectUpdate
from app.schemas.common import Message
from app.services import audit

router = APIRouter(tags=["projects"])


@router.get("/organizations/{organization_id}/projects", response_model=list[ProjectOut])
def list_projects(organization_id: int, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.PROJECT_READ)
    from sqlalchemy import select
    return db.scalars(select(Project).where(Project.organization_id == organization_id)).all()


@router.post("/organizations/{organization_id}/projects", response_model=ProjectOut, status_code=201)
def create_project(organization_id: int, payload: ProjectCreate, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.PROJECT_MANAGE)
    project = Project(organization_id=organization_id, name=payload.name,
                      description=payload.description)
    db.add(project)
    db.commit()
    audit.record(db, action="project.create", actor_id=ctx.user.id,
                 organization_id=organization_id, resource_type="project", resource_id=project.id)
    return project


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project: ProjectDep):
    obj, ctx = project
    ctx.require(rbac.PROJECT_READ)
    return obj


@router.patch("/projects/{project_id}", response_model=ProjectOut)
def update_project(project: ProjectDep, payload: ProjectUpdate, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.PROJECT_MANAGE)
    if payload.name is not None:
        obj.name = payload.name
    if payload.description is not None:
        obj.description = payload.description
    db.commit()
    audit.record(db, action="project.update", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="project", resource_id=obj.id)
    return obj


@router.delete("/projects/{project_id}", response_model=Message)
def delete_project(project: ProjectDep, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.PROJECT_MANAGE)
    db.delete(obj)
    db.commit()
    audit.record(db, action="project.delete", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="project", resource_id=obj.id)
    return Message(detail="Project deleted")
