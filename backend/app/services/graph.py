"""Builds a security graph (nodes + edges) for a project from the relational
model plus explicit correlation edges. No graph database required."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assets import Asset, AssetRelationship
from app.models.correlation import Correlation, FindingTechnique
from app.models.detection import Alert
from app.models.scans import Finding
from app.schemas.misc import GraphEdge, GraphNode, GraphOut


def build_graph(db: Session, project_id: int, max_findings: int = 200) -> GraphOut:
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def add_node(kind: str, ident: int | str, label: str, meta: dict | None = None) -> str:
        node_id = f"{kind}:{ident}"
        if node_id not in nodes:
            nodes[node_id] = GraphNode(id=node_id, kind=kind, label=label, meta=meta or {})
        return node_id

    project_node = add_node("project", project_id, "Project")

    assets = db.scalars(select(Asset).where(Asset.project_id == project_id)).all()
    for a in assets:
        an = add_node("asset", a.id, a.name or a.value,
                      {"type": a.type.value, "criticality": a.criticality.value,
                       "authorization": a.authorization_status.value})
        edges.append(GraphEdge(source=project_node, target=an, relation="contains"))

    for rel in db.scalars(
        select(AssetRelationship).where(AssetRelationship.project_id == project_id)
    ).all():
        edges.append(GraphEdge(source=f"asset:{rel.source_asset_id}",
                               target=f"asset:{rel.target_asset_id}", relation=rel.relation))

    findings = db.scalars(
        select(Finding).where(Finding.project_id == project_id)
        .order_by(Finding.risk_score.desc()).limit(max_findings)
    ).all()
    finding_ids = set()
    for f in findings:
        finding_ids.add(f.id)
        fn = add_node("finding", f.id, f.title,
                      {"severity": f.severity.value, "risk": f.risk_score,
                       "status": f.status.value})
        edges.append(GraphEdge(source=f"asset:{f.asset_id}", target=fn, relation="has_finding"))

    if finding_ids:
        for ft in db.scalars(
            select(FindingTechnique).where(FindingTechnique.finding_id.in_(finding_ids))
        ).all():
            tn = add_node("technique", ft.technique_id, ft.technique_id)
            edges.append(GraphEdge(source=f"finding:{ft.finding_id}", target=tn,
                                   relation=ft.relationship_kind.lower()))

    for al in db.scalars(select(Alert).where(Alert.project_id == project_id)).all():
        an = add_node("alert", al.id, al.title,
                      {"severity": al.severity.value, "state": al.state.value})
        for tech in (al.mitre_technique_ids or []):
            tn = add_node("technique", tech, tech)
            edges.append(GraphEdge(source=an, target=tn, relation="observed"))

    for c in db.scalars(select(Correlation).where(Correlation.project_id == project_id)).all():
        src = f"{c.source_type}:{c.source_id}"
        tgt = f"{c.target_type}:{c.target_id}"
        if src in nodes and tgt in nodes:
            edges.append(GraphEdge(source=src, target=tgt, relation=c.relation, reason=c.reason))

    return GraphOut(nodes=list(nodes.values()), edges=edges)
