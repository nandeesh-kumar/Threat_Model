#!/usr/bin/env python3
"""Generate a tabbed STRIDE threat-modelling HTML report."""

from __future__ import annotations

import html
import json
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from string import Template


@dataclass
class DataFlow:
    id: str
    source: str
    destination: str
    label: str
    data: str


@dataclass
class DfdElement:
    id: str
    name: str
    kind: str
    notes: str = ""


@dataclass
class Threat:
    id: str
    title: str
    stride: str
    element: str
    dfd_ref: str
    description: str
    impact: str
    likelihood: str
    risk: str
    mitigations: list[str] = field(default_factory=list)
    status: str = "Open"
    owner: str = ""
    remarks: str = ""


@dataclass
class ThreatModel:
    title: str
    system_name: str
    version: str
    author: str
    description: str
    assumptions: list[str]
    assets: list[str]
    trust_boundaries: list[str]
    components: list[str]
    dfd_elements: list[DfdElement]
    data_flows: list[DataFlow]
    threats: list[Threat]


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _risk_class(risk: str) -> str:
    mapping = {
        "Critical": "risk-critical",
        "High": "risk-high",
        "Medium": "risk-medium",
        "Low": "risk-low",
    }
    return mapping.get(risk, "risk-medium")


def _stride_counts(threats: list[Threat]) -> dict[str, int]:
    categories = [
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    ]
    counts = {name: 0 for name in categories}
    for threat in threats:
        if threat.stride in counts:
            counts[threat.stride] += 1
    return counts


def _risk_counts(threats: list[Threat]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for threat in threats:
        if threat.risk in counts:
            counts[threat.risk] += 1
    return counts


def load_mermaid_dfd(mermaid_path: Path) -> str:
    """Read the DFD source from disk so the diagram is not embedded in Python."""
    return mermaid_path.read_text(encoding="utf-8").strip()


def load_all_mermaid_dfds(mermaid_path: Path | None) -> list[tuple[str, str]]:
    """Load all Mermaid DFD files from a folder or a single file."""
    base_path = mermaid_path or Path(__file__).parent / "mermaid-dfd"
    if base_path.is_file():
        return [(base_path.name, load_mermaid_dfd(base_path))]
    if not base_path.exists() or not base_path.is_dir():
        return []

    files = sorted(base_path.glob("*.mermaid"), key=lambda p: p.name)
    return [(file.name, load_mermaid_dfd(file)) for file in files if file.is_file()]


def load_threat_model(data_path: Path) -> ThreatModel:
    """Load the report configuration from a JSON file."""
    payload = json.loads(data_path.read_text(encoding="utf-8"))
    return ThreatModel(
        title=payload["title"],
        system_name=payload["system_name"],
        version=payload["version"],
        author=payload["author"],
        description=payload["description"],
        assumptions=payload.get("assumptions", []),
        assets=payload.get("assets", []),
        trust_boundaries=payload.get("trust_boundaries", []),
        components=payload.get("components", []),
        dfd_elements=[DfdElement(**item) for item in payload.get("dfd_elements", [])],
        data_flows=[DataFlow(**item) for item in payload.get("data_flows", [])],
        threats=[
            Threat(
                id=item["id"],
                title=item["title"],
                stride=item["stride"],
                element=item["element"],
                dfd_ref=item["dfd_ref"],
                description=item["description"],
                impact=item["impact"],
                likelihood=item["likelihood"],
                risk=item["risk"],
                mitigations=item.get("mitigations", []),
                status=item.get("status", "Open"),
                owner=item.get("owner", ""),
                remarks=item.get("remarks", ""),
            )
            for item in payload.get("threats", [])
        ],
    )


def sample_model() -> ThreatModel:
    data_file = Path(__file__).with_name("threat_model_data.json")
    if not data_file.exists():
        raise FileNotFoundError(f"Missing report data file: {data_file}")
    return load_threat_model(data_file)


def fetch_mermaid_bundle() -> str:
    """Download Mermaid and inline it into the generated HTML so the output is self-contained."""
    url = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            return response.read().decode("utf-8")
    except Exception as exc:
        raise RuntimeError(f"Unable to fetch Mermaid bundle from {url}: {exc}") from exc


def render_html(model: ThreatModel, mermaid_path: Path | None = None, template_path: Path | None = None) -> str:
    stride_counts = _stride_counts(model.threats)
    risk_counts = _risk_counts(model.threats)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    open_count = sum(1 for t in model.threats if t.status.lower() == "open")

    assumption_items = "".join(f"<li>{_esc(item)}</li>" for item in model.assumptions)
    asset_items = "".join(f"<li>{_esc(item)}</li>" for item in model.assets)
    boundary_items = "".join(f"<li>{_esc(item)}</li>" for item in model.trust_boundaries)
    component_chips = "".join(f'<span class="chip">{_esc(item)}</span>' for item in model.components)

    stride_cards = "".join(
        f"""
        <div class="stat-card">
          <div class="stat-label">{_esc(name)}</div>
          <div class="stat-value">{count}</div>
        </div>
        """
        for name, count in stride_counts.items()
    )
    risk_cards = "".join(
        f"""
        <div class="stat-card {_risk_class(name)}">
          <div class="stat-label">{_esc(name)}</div>
          <div class="stat-value">{count}</div>
        </div>
        """
        for name, count in risk_counts.items()
    )

    element_rows = "".join(
        f"""
        <tr>
          <td>{_esc(el.id)}</td>
          <td>{_esc(el.name)}</td>
          <td>{_esc(el.kind)}</td>
          <td>{_esc(el.notes)}</td>
        </tr>
        """
        for el in model.dfd_elements
    )

    flow_rows = "".join(
        f"""
        <tr>
          <td>{_esc(flow.id)}</td>
          <td>{_esc(flow.source)}</td>
          <td>{_esc(flow.destination)}</td>
          <td>{_esc(flow.label)}</td>
          <td>{_esc(flow.data)}</td>
        </tr>
        """
        for flow in model.data_flows
    )

    threat_rows = []
    threat_details = []
    for threat in model.threats:
        mitigations = "".join(f"<li>{_esc(item)}</li>" for item in threat.mitigations)
        threat_rows.append(
            f"""
            <tr>
              <td><a href="#threat-{_esc(threat.id)}">{_esc(threat.id)}</a></td>
              <td>{_esc(threat.title)}</td>
              <td><span class="badge">{_esc(threat.stride)}</span></td>
              <td>{_esc(threat.dfd_ref)}</td>
              <td><span class="badge {_risk_class(threat.risk)}">{_esc(threat.risk)}</span></td>
              <td>{_esc(threat.status)}</td>
            </tr>
            """
        )
        threat_details.append(
            f"""
            <article class="threat-card {_risk_class(threat.risk)}" id="threat-{_esc(threat.id)}" data-id="{_esc(threat.id)}" data-stride="{_esc(threat.stride)}" data-status="{_esc(threat.status)}" data-risk="{_esc(threat.risk)}" data-owner="{_esc(threat.owner)}" data-description="{_esc(threat.description)}" data-impact="{_esc(threat.impact)}" data-likelihood="{_esc(threat.likelihood)}" data-mitigations="{_esc(' | '.join(threat.mitigations))}" data-remarks="{_esc(threat.remarks)}">
              <header>
                <h3>{_esc(threat.id)} — {_esc(threat.title)}</h3>
                <div class="meta">
                  <span class="badge">{_esc(threat.stride)}</span>
                  <span class="badge">{_esc(threat.dfd_ref)}</span>
                  <span class="badge {_risk_class(threat.risk)}">{_esc(threat.risk)}</span>
                  <span class="badge">{_esc(threat.status)}</span>
                </div>
              </header>
              <p><strong>DFD element:</strong> {_esc(threat.element)}</p>
              <p>{_esc(threat.description)}</p>
              <div class="split">
                <p><strong>Impact:</strong> {_esc(threat.impact)}</p>
                <p><strong>Likelihood:</strong> {_esc(threat.likelihood)}</p>
              </div>
              <p><strong>Mitigations</strong></p>
              <ul>{mitigations}</ul>
              <div class="threat-editor-grid">
                <label>
                  <span>Owner</span>
                  <input type="text" class="threat-field" data-field="owner" value="{_esc(threat.owner)}" placeholder="Assigned owner" />
                </label>
                <label>
                  <span>Status</span>
                  <select class="threat-field" data-field="status">
                    <option value="Open" {'selected' if threat.status == 'Open' else ''}>Open</option>
                    <option value="Mitigated" {'selected' if threat.status == 'Mitigated' else ''}>Mitigated</option>
                    <option value="Accepted" {'selected' if threat.status == 'Accepted' else ''}>Accepted</option>
                    <option value="Rejected" {'selected' if threat.status == 'Rejected' else ''}>Rejected</option>
                  </select>
                </label>
              </div>
              <label>
                <span>Remarks</span>
                <textarea class="threat-field" data-field="remarks" rows="4" placeholder="Add notes, caveats, or follow-up actions">{_esc(threat.remarks)}</textarea>
              </label>
            </article>
            """
        )

    mermaid_bundle = fetch_mermaid_bundle()
    model_json = json.dumps(asdict(model), indent=2)
    mermaid_sources = load_all_mermaid_dfds(mermaid_path)
    dfd_cards = "".join(
        f"""
        <div class="card">
          <h3>{_esc(name)}</h3>
          <div class="dfd-source mermaid">{content}</div>
        </div>
        """
        for name, content in mermaid_sources
    ) or """
        <div class="card">
          <h3>No Mermaid DFD files found</h3>
          <p>Check the <code>mermaid-dfd</code> directory or pass a Mermaid file/folder to <code>write_report</code>.</p>
        </div>
    """

    template_file = template_path or Path(__file__).with_name("report_template.html")
    template = Template(template_file.read_text(encoding="utf-8"))
    rendered = template.safe_substitute(
        title=model.title,
        system_name=model.system_name,
        version=model.version,
        author=model.author,
        generated=generated,
        description=model.description,
        assumption_items=assumption_items,
        asset_items=asset_items,
        boundary_items=boundary_items,
        component_chips=component_chips,
        total_threats=len(model.threats),
        open_count=open_count,
        critical_count=risk_counts.get("Critical", 0),
        high_count=risk_counts.get("High", 0),
        stride_cards=stride_cards,
        risk_cards=risk_cards,
        threat_rows="".join(threat_rows),
        dfd_cards=dfd_cards,
        element_rows=element_rows,
        flow_rows=flow_rows,
        threat_details="".join(threat_details),
        model_json=model_json,
        mermaid_bundle=mermaid_bundle,
    )
    return rendered


def write_report(
    output_path: Path,
    model: ThreatModel | None = None,
    mermaid_path: Path | None = None,
    template_path: Path | None = None,
) -> Path:
    model = model or sample_model()
    output_path.write_text(render_html(model, mermaid_path, template_path), encoding="utf-8")
    return output_path


if __name__ == "__main__":
    out = Path(__file__).with_name("threat_model_report.html")
    write_report(out)
    print(f"Wrote {out}")
