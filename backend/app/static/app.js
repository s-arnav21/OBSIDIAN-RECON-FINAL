const scenarios = [
  { id: "generic_local_web_validation", label: "Full controlled chain (live loopback fixture)" },
  { id: "public_app_validation", label: "Public application validation (fixture / DVWA lab)" },
];

const progressStages = [
  "Target validation", "Reconnaissance", "Service discovery",
  "Vulnerability discovery", "Active validation", "MITRE mapping",
  "Attack-path analysis", "Persistence",
];

const environmentalFindingTypes = new Set([
  "service_scan", "port_scan", "network_scan", "nmap_scan", "nuclei_scan",
]);

const $ = (selector) => document.querySelector(selector);

async function requestJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (_error) {
    throw new Error("Backend is unavailable. Confirm that Obsidian Recon is running.");
  }
  let body;
  try {
    body = await response.json();
  } catch (_error) {
    throw new Error("The backend returned an unreadable response.");
  }
  if (!response.ok) {
    const detail = body.detail;
    const message = typeof detail === "string"
      ? detail
      : detail?.message || "The backend could not complete this request.";
    const error = new Error(message);
    error.code = typeof detail === "object" ? detail?.code : null;
    error.detail = detail;
    throw error;
  }
  return body;
}

function postJson(url, body) {
  return requestJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function statusClass(value) {
  const normalized = String(value || "unknown").toLowerCase().replaceAll("_", "-");
  if (["confirmed", "completed", "ready"].includes(normalized)) return "success";
  if (["failed", "verification-failed", "rejected", "unavailable", "expired"].includes(normalized)) return "danger";
  if (["manual-review", "degraded", "not-configured", "blocked"].includes(normalized)) return "warning";
  return normalized;
}

function displayStatus(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function displayFindingType(value) {
  if (value === "command_execution") {
    return "Controlled Command-Execution Simulation";
  }
  return displayStatus(value || "Unknown finding");
}

function findingValidationPairs(data) {
  const pairs = new Map();
  const addPair = (finding = {}, validation = {}, presentation = null) => {
    const location = presentation?.location || {};
    const presentedValidation = presentation?.validation || {};
    const mitre = presentation?.mitre || {};
    const derivedFinding = {
      finding_id: presentation?.finding_id,
      target: location.target,
      endpoint: location.endpoint,
      http_method: location.http_method,
      parameter_name: location.parameter_name,
      parameter_location: location.parameter_location,
      vulnerability_type: presentation?.vulnerability_type,
      validation_status: presentedValidation.status,
      validation_confidence: presentedValidation.confidence,
      validator_id: presentedValidation.validator,
      mitre_technique_id: mitre.technique_id,
      mitre_technique_name: mitre.technique_name,
      mitre_tactic: mitre.tactic,
      provides: presentation?.provides,
    };
    const cleanDerivedFinding = Object.fromEntries(
      Object.entries(derivedFinding).filter(([, value]) => value !== undefined),
    );
    const mergedFinding = { ...cleanDerivedFinding, ...finding };
    const mergedValidation = { ...presentedValidation, ...validation };
    const key = mergedFinding.finding_id
      || mergedFinding.id
      || [mergedFinding.vulnerability_type, mergedFinding.target, mergedFinding.endpoint]
        .filter(Boolean).join("|");
    if (!key) return;
    const existing = pairs.get(key);
    pairs.set(key, existing ? {
      finding: { ...mergedFinding, ...existing.finding },
      validation: { ...mergedValidation, ...existing.validation },
      presentation: existing.presentation || presentation,
    } : {
      finding: mergedFinding,
      validation: mergedValidation,
      presentation,
    });
  };

  const presentationById = new Map();
  const rememberPresentation = (presentation) => {
    if (!presentation?.finding_id) return;
    if (!presentationById.has(presentation.finding_id)) {
      presentationById.set(presentation.finding_id, presentation);
    }
  };
  (Array.isArray(data.finding_presentations) ? data.finding_presentations : [])
    .forEach(rememberPresentation);
  const attackFlow = data.attack_flow || {};
  [attackFlow.multi_stage_paths, attackFlow.standalone_findings]
    .filter(Array.isArray)
    .flat()
    .forEach((chain) => (chain.steps || []).forEach((step) => {
      rememberPresentation(step.finding_presentation);
    }));

  if (data.finding) {
    const technique = data.technique || {};
    const finding = {
      ...data.finding,
      mitre_technique_id:
        data.finding.mitre_technique_id || technique.technique_id,
      mitre_technique_name:
        data.finding.mitre_technique_name || technique.technique_name,
    };
    addPair(
      finding,
      data.validation_result || {},
      presentationById.get(finding.finding_id || finding.id),
    );
  }
  if (data.validations && !Array.isArray(data.validations)) {
    Object.values(data.validations).forEach((item) => {
      const finding = item?.finding || {};
      addPair(
        finding,
        item?.validation_result || {},
        presentationById.get(finding.finding_id || finding.id),
      );
    });
  }
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const validations = Array.isArray(data.validations) ? data.validations : [];
  findings.forEach((finding, index) => addPair(
    finding,
    validations[index] || finding.validations?.at(-1) || {},
    presentationById.get(finding.finding_id || finding.id),
  ));
  presentationById.forEach((presentation) => addPair(
    {},
    presentation.validation || {},
    presentation,
  ));
  return [...pairs.values()];
}

function resultChains(data) {
  if (Array.isArray(data.chains)) return data.chains;
  if (Array.isArray(data.chain_result?.chains)) return data.chain_result.chains;
  return [];
}

function techniqueFor(finding) {
  if (finding.mitre_technique_id) {
    return {
      id: finding.mitre_technique_id,
      name: finding.mitre_technique_name,
      tactic: finding.mitre_tactic,
    };
  }
  const mapping = Array.isArray(finding.mitre_mappings)
    ? finding.mitre_mappings[0]
    : null;
  return { id: mapping?.technique_id, name: mapping?.technique_name, tactic: mapping?.tactic };
}

function computeSummary(data) {
  const pairs = findingValidationPairs(data);
  const presentations = pairs.map(({ presentation }) => presentation).filter(Boolean);
  const statuses = pairs.map(({ finding, validation }) =>
    validation.status || finding.validation_status || finding.status || "detected");
  const techniques = new Set(
    pairs.map(({ finding }) => techniqueFor(finding).id).filter(Boolean),
  );
  const assets = new Set(pairs.map(({ finding }) => finding.asset_id).filter(Boolean));
  if (data.asset?.asset_id) assets.add(data.asset.asset_id);
  return {
    status: data.status || data.overall_status || "completed",
    assets: assets.size,
    services: Array.isArray(data.services) ? data.services.length : null,
    candidates: pairs.length,
    confirmed: statuses.filter((status) => status === "confirmed").length,
    rejected: statuses.filter((status) => status === "rejected").length,
    manualReview: statuses.filter((status) => status === "manual_review").length,
    techniques: techniques.size,
    chains: resultChains(data).length,
    highRisk: presentations.filter((item) => item.risk?.rating === "High").length,
    criticalRisk: presentations.filter((item) => item.risk?.rating === "Critical").length,
  };
}

function addSummaryCard(container, label, value, tone = "") {
  const card = document.createElement("article");
  card.className = `summary-card ${tone}`.trim();
  const number = document.createElement("strong");
  number.textContent = value === null ? "—" : String(value);
  const caption = document.createElement("span");
  caption.textContent = label;
  card.append(number, caption);
  container.append(card);
}

function createStatusPill(status) {
  const pill = document.createElement("span");
  pill.className = `status-pill ${statusClass(status)}`;
  pill.textContent = displayStatus(status);
  return pill;
}

function renderSummary(data) {
  const summary = computeSummary(data);
  const container = $("#summary-cards");
  container.replaceChildren();
  [
    ["Assessment status", displayStatus(summary.status), statusClass(summary.status)],
    ["Assets", summary.assets], ["Services", summary.services],
    ["Candidate findings", summary.candidates],
    ["Confirmed", summary.confirmed, "success"],
    ["Rejected / review", `${summary.rejected} / ${summary.manualReview}`, summary.manualReview ? "warning" : ""],
    ["MITRE techniques", summary.techniques], ["Attack chains", summary.chains],
    ["High / critical risk", `${summary.highRisk} / ${summary.criticalRisk}`, summary.criticalRisk ? "danger" : summary.highRisk ? "warning" : ""],
  ].forEach(([label, value, tone]) => addSummaryCard(container, label, value, tone));
}

function appendLabeledText(container, label, value) {
  if (value === null || value === undefined || value === "") return;
  const block = document.createElement("div");
  block.className = "detail-field";
  const heading = document.createElement("strong");
  heading.textContent = label;
  const content = document.createElement("span");
  content.textContent = String(value);
  block.append(heading, content);
  container.append(block);
}

function appendList(container, headingText, values) {
  if (!Array.isArray(values) || values.length === 0) return;
  const section = document.createElement("section");
  const heading = document.createElement("h4");
  heading.textContent = headingText;
  const list = document.createElement("ul");
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    list.append(item);
  });
  section.append(heading, list);
  container.append(section);
}

function createRiskPill(rating) {
  const pill = document.createElement("span");
  const normalized = String(rating || "Not rated").toLowerCase().replaceAll(" ", "-");
  pill.className = `risk-pill risk-${normalized}`;
  pill.textContent = rating || "Not rated";
  return pill;
}

function renderProofDetails(presentation) {
  const details = document.createElement("details");
  details.className = "proof-details";
  const summary = document.createElement("summary");
  summary.textContent = presentation?.poc?.available
    ? "VIEW PROOF OF CONCEPT"
    : "VIEW EVIDENCE";
  const panel = document.createElement("div");
  panel.className = "proof-panel";
  if (!presentation) {
    const note = document.createElement("p");
    note.textContent = "Human-readable presentation data is unavailable for this persisted result.";
    panel.append(note);
    details.append(summary, panel);
    return details;
  }

  const location = presentation.location || {};
  const validation = presentation.validation || {};
  const poc = presentation.poc || {};
  const risk = presentation.risk || {};
  const mitre = presentation.mitre;
  const proofIntro = document.createElement("p");
  proofIntro.className = "proof-intro";
  proofIntro.textContent = `${poc.label || "Evidence"} · ${poc.subtitle || "Evidence and reproduction steps."}`;
  panel.append(proofIntro);
  const overview = document.createElement("div");
  overview.className = "detail-grid";
  appendLabeledText(overview, "Target", location.target);
  appendLabeledText(overview, "Endpoint", location.endpoint);
  appendLabeledText(overview, "HTTP method", location.http_method);
  appendLabeledText(overview, "Parameter", location.parameter_name);
  appendLabeledText(overview, "Parameter location", location.parameter_location);
  appendLabeledText(overview, "Verification method", poc.verification_method);
  appendLabeledText(overview, "Validator method", validation.method);
  appendLabeledText(overview, "Validation", displayStatus(validation.status));
  appendLabeledText(overview, "Confidence", typeof validation.confidence === "number" ? `${Math.round(validation.confidence * 100)}%` : null);
  panel.append(overview);

  if (Array.isArray(poc.detection_methods) && poc.detection_methods.length) {
    const methodsSection = document.createElement("section");
    const methodsHeading = document.createElement("h4");
    methodsHeading.textContent = "Detection methods";
    const methodsGrid = document.createElement("div");
    methodsGrid.className = "detection-method-grid";
    poc.detection_methods.forEach((method) => {
      const card = document.createElement("article");
      card.className = "detection-method-card";
      const name = document.createElement("strong");
      name.textContent = method.name;
      card.append(name, createStatusPill(method.state));
      appendLabeledText(card, "Result", method.summary || displayStatus(method.reason));
      methodsGrid.append(card);
    });
    methodsSection.append(methodsHeading, methodsGrid);
    panel.append(methodsSection);
  }

  appendList(panel, "Reproduction steps", poc.steps);
  if (Array.isArray(poc.requests) && poc.requests.length) {
    const requests = document.createElement("section");
    const heading = document.createElement("h4");
    heading.textContent = "Controlled request shapes";
    requests.append(heading);
    poc.requests.forEach((request) => {
      const label = document.createElement("strong");
      label.textContent = request.label;
      const block = document.createElement("pre");
      block.textContent = request.request;
      requests.append(label, block);
    });
    panel.append(requests);
  }
  appendLabeledText(panel, "Request detail", poc.request_note);
  appendLabeledText(panel, "Observed evidence", JSON.stringify(poc.observed_evidence || {}, null, 2));
  appendLabeledText(panel, "Interpretation", poc.interpretation);
  appendLabeledText(panel, "Safety note", poc.safety_note);
  if (mitre) {
    appendLabeledText(panel, "MITRE ATT&CK", `${mitre.technique_id} — ${mitre.technique_name} · ${mitre.tactic}`);
  } else {
    appendLabeledText(panel, "MITRE ATT&CK", "Unmapped");
  }
  appendList(panel, "Technical impact", risk.technical_impact);
  if (risk.cia) {
    appendLabeledText(panel, "CIA impact", `Confidentiality: ${risk.cia.confidentiality} · Integrity: ${risk.cia.integrity} · Availability: ${risk.cia.availability}`);
  }
  appendLabeledText(panel, "Business-risk rationale", risk.rationale);
  if (risk.business) {
    appendLabeledText(panel, "Confidentiality impact", risk.business.confidentiality);
    appendLabeledText(panel, "Integrity impact", risk.business.integrity);
    appendLabeledText(panel, "Availability impact", risk.business.availability);
    appendList(panel, "Potential business consequences", risk.business.consequences);
  }
  appendLabeledText(panel, "Scope", risk.scope_note);
  appendLabeledText(panel, "CVSS", risk.cvss);
  appendLabeledText(panel, "Rating notice", risk.notice);
  details.append(summary, panel);
  return details;
}

function renderFindings(data) {
  const pairs = findingValidationPairs(data);
  const body = $("#findings-body");
  body.replaceChildren();
  $("#finding-count").textContent = String(pairs.length);
  $("#findings-empty").hidden = pairs.length !== 0;
  $(".table-wrap").hidden = pairs.length === 0;
  pairs.forEach(({ finding, validation, presentation }) => {
    const status = validation.status || finding.validation_status || finding.status || "detected";
    const technique = techniqueFor(finding);
    const row = document.createElement("tr");
    const findingCell = document.createElement("td");
    const name = document.createElement("strong");
    name.textContent = displayFindingType(finding.vulnerability_type);
    const id = document.createElement("small");
    id.textContent = finding.finding_id || finding.id || "";
    findingCell.append(name, id);
    row.append(findingCell);
    [
      finding.severity || "—",
      finding.endpoint || "—",
    ].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });
    const statusCell = document.createElement("td");
    statusCell.append(createStatusPill(status));
    row.append(statusCell);
    const confidenceCell = document.createElement("td");
    const confidence = validation.confidence ?? finding.validation_confidence;
    confidenceCell.textContent = typeof confidence === "number"
      ? `${Math.round(confidence * 100)}%`
      : "—";
    row.append(confidenceCell);
    const validatorCell = document.createElement("td");
    const validatorName = validation.validator
      || finding.validator_id
      || finding.template_id
      || "—";
    validatorCell.textContent = displayStatus(validatorName);
    row.append(validatorCell);
    const mitreCell = document.createElement("td");
    mitreCell.textContent = technique.id
      ? `${technique.id}${technique.name ? `\n${technique.name}` : ""}${(presentation?.mitre?.tactic || technique.tactic) ? `\n${presentation?.mitre?.tactic || technique.tactic}` : ""}`
      : "Unmapped";
    row.append(mitreCell);
    const capabilitiesCell = document.createElement("td");
    const capabilities = presentation?.provides || finding.provides || [];
    capabilitiesCell.textContent = Array.isArray(capabilities) && capabilities.length
      ? capabilities.map(displayStatus).join("\n")
      : "None recorded";
    row.append(capabilitiesCell);
    const riskCell = document.createElement("td");
    riskCell.append(createRiskPill(presentation?.risk?.rating));
    row.append(riskCell);
    const proofCell = document.createElement("td");
    const proofLabel = document.createElement("span");
    proofLabel.className = "poc-label";
    proofLabel.textContent = presentation?.poc?.label || "Unavailable";
    proofCell.append(proofLabel);
    if (presentation?.validation?.reason) {
      const evidenceSummary = document.createElement("small");
      evidenceSummary.className = "evidence-summary";
      evidenceSummary.textContent = displayStatus(presentation.validation.reason);
      proofCell.append(evidenceSummary);
    }
    proofCell.append(renderProofDetails(presentation));
    row.append(proofCell);
    body.append(row);
  });
}

function renderAgentActivity(data) {
  const run = data.agent_run || data.agent_activity || null;
  const steps = Array.isArray(run?.steps) ? run.steps : [];
  const list = $("#agent-steps");
  const empty = $("#agent-empty");
  const status = $("#agent-status");
  list.replaceChildren();
  empty.hidden = Boolean(run);
  status.className = `status-pill ${statusClass(run?.status || "queued")}`;
  status.textContent = run ? displayStatus(run.status || "unknown") : "Not run";
  if (!run) return;

  steps.forEach((step) => {
    const action = step.proposed_action || {};
    const policy = step.policy_decision || {};
    const observation = step.observation || {};
    const finalFinding = (run.final_state?.findings || []).find(
      (finding) => finding.finding_id === action.finding_id,
    ) || {};
    const item = document.createElement("li");
    item.className = "agent-step";
    const header = document.createElement("div");
    header.className = "agent-step-header";
    const title = document.createElement("strong");
    title.textContent = `Step ${step.step_number || "—"} / ${run.steps_used || steps.length} · ${displayStatus(action.tool_id || "registered tool")}`;
    header.append(title, createStatusPill(observation.execution_status || policy.code));
    item.append(header);

    const trace = document.createElement("div");
    trace.className = "agent-trace-grid";
    appendLabeledText(trace, "Planner proposal", action.reason || "No proposal summary returned");
    appendLabeledText(
      trace,
      "Policy Gate",
      `${policy.allowed ? "APPROVED" : "DENIED"} · ${displayStatus(policy.code || observation.policy_decision)}`,
    );
    appendLabeledText(trace, "Selected registered tool", action.tool_id);
    appendLabeledText(trace, "Finding", action.finding_id);
    appendLabeledText(trace, "Observation", observation.summary);
    appendLabeledText(
      trace,
      "Deterministic validator",
      observation.validation_status
        ? `${displayStatus(observation.validation_status)}${typeof finalFinding.validation_confidence === "number" ? ` — ${Math.round(finalFinding.validation_confidence * 100)}%` : ""}`
        : null,
    );
    appendLabeledText(
      trace,
      "MITRE ATT&CK",
      finalFinding.mitre_technique_id
        ? `${finalFinding.mitre_technique_id} — ${finalFinding.mitre_technique_name || "Mapped technique"}`
        : null,
    );
    appendLabeledText(
      trace,
      "Capabilities gained",
      Array.isArray(observation.capabilities_gained) && observation.capabilities_gained.length
        ? observation.capabilities_gained.map(displayStatus).join(", ")
        : "None",
    );
    item.append(trace);
    list.append(item);
  });

  if (!steps.length) {
    const note = document.createElement("li");
    note.className = "empty-state";
    note.textContent = `Agent stopped without an executable action: ${displayStatus(run.stop_reason || "no action proposed")}.`;
    list.append(note);
  }
}

function renderChains(data) {
  const chains = resultChains(data);
  const attackFlow = data.attack_flow || {};
  const multiStage = Array.isArray(attackFlow.multi_stage_paths)
    ? attackFlow.multi_stage_paths
    : [];
  const standalone = Array.isArray(attackFlow.standalone_findings)
    ? attackFlow.standalone_findings
    : [];
  const presentedChains = [...multiStage, ...standalone];
  const list = $("#chain-list");
  list.replaceChildren();
  $("#chain-count").textContent = String(chains.length);
  $("#chains-empty").hidden = chains.length !== 0;
  if (multiStage.length) {
    const multiHeading = document.createElement("h4");
    multiHeading.className = "flow-group-heading";
    multiHeading.textContent = "Multi-stage attack paths";
    list.append(multiHeading);
  }
  presentedChains.forEach((chain, chainIndex) => {
    if (chainIndex === multiStage.length && standalone.length) {
      const standaloneHeading = document.createElement("h4");
      standaloneHeading.className = "flow-group-heading";
      standaloneHeading.textContent = "Standalone validated findings";
      list.append(standaloneHeading);
    }
    const card = document.createElement("article");
    card.className = "chain-card";
    const header = document.createElement("div");
    header.className = "chain-header";
    const title = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = chain.chain_id || chain.id || "Attack path";
    const confidence = document.createElement("small");
    confidence.textContent = typeof chain.confidence === "number"
      ? `${Math.round(chain.confidence * 100)}% confidence`
      : "";
    title.append(heading, confidence);
    const badges = document.createElement("div");
    badges.className = "chain-badges";
    badges.append(createRiskPill(chain.cumulative_risk), createStatusPill(chain.status));
    header.append(title, badges);
    const steps = Array.isArray(chain.steps) ? [...chain.steps] : [];
    steps.sort((left, right) => (left.step_number || 0) - (right.step_number || 0));
    const contextSteps = steps.filter((step) =>
      step.step_type === "environmental_fact"
      || environmentalFindingTypes.has(step.vulnerability_type));
    const actionSteps = steps.filter((step) => !contextSteps.includes(step));
    if (contextSteps.length) {
      const prerequisites = document.createElement("div");
      prerequisites.className = "chain-prerequisites";
      const label = document.createElement("strong");
      label.textContent = "Observed prerequisite";
      const values = document.createElement("span");
      values.textContent = contextSteps.map((step) => {
        const capabilities = Array.isArray(step.provides)
          ? step.provides.map(displayStatus).join(", ")
          : "reachable service";
        return `${step.target || "Target"} · ${capabilities}`;
      }).join(" · ");
      prerequisites.append(label, values);
      card.append(header, prerequisites);
    } else {
      card.append(header);
    }
    const flow = document.createElement("div");
    flow.className = "chain-flow";
    actionSteps.forEach((step, index) => {
      const node = document.createElement("div");
      node.className = `chain-node ${step.mitre_technique_id ? "technique" : "unmapped"}`;
      const kicker = document.createElement("span");
      kicker.textContent = step.mitre_technique_id || "Validated finding";
      const nodeTitle = document.createElement("strong");
      nodeTitle.textContent = step.mitre_technique_name
        || displayFindingType(step.vulnerability_type || step.capability);
      const detail = step.finding_presentation || {};
      const location = detail.location || {};
      const metadata = document.createElement("small");
      metadata.textContent = [location.endpoint || step.target, displayStatus(step.validation_status)]
        .filter(Boolean).join(" · ");
      node.append(kicker, nodeTitle, metadata);
      appendLabeledText(node, "Tactic", detail.mitre?.tactic || step.mitre_tactic);
      appendLabeledText(node, "Finding", displayFindingType(detail.vulnerability_type || step.vulnerability_type));
      appendLabeledText(node, "Endpoint", location.endpoint);
      appendLabeledText(node, "Validation", displayStatus(detail.validation?.status || step.validation_status));
      appendLabeledText(node, "Confidence", typeof (detail.validation?.confidence ?? step.validation_confidence) === "number" ? `${Math.round((detail.validation?.confidence ?? step.validation_confidence) * 100)}%` : null);
      appendList(node, "Capabilities gained", (step.provides || []).map(displayStatus));
      appendLabeledText(node, "Safety boundary", detail.poc?.safety_note);
      flow.append(node);
      if (index < actionSteps.length - 1) {
        const connector = document.createElement("div");
        connector.className = "chain-connector";
        const nextStep = actionSteps[index + 1];
        const dependency = (chain.dependencies || []).filter((item) =>
          item.provider_finding_id === step.finding_id
          && item.consumer_finding_id === nextStep.finding_id);
        const capability = dependency.length
          ? dependency.map((item) => `${displayStatus(item.capability)} (${item.requirement})`).join(", ")
          : Array.isArray(step.provides) && step.provides.length
            ? step.provides.map(displayStatus).join(", ")
            : step.capability;
        const label = document.createElement("span");
        label.textContent = dependency.length
          ? `PROVIDES ${capability} · SATISFIES PREREQUISITE FOR NEXT STEP`
          : capability || "enables";
        connector.append(label, document.createTextNode("↓"));
        flow.append(connector);
      }
    });
    const impact = document.createElement("div");
    impact.className = "chain-impact";
    appendLabeledText(impact, "Attack path impact", chain.impact_summary);
    appendLabeledText(impact, "Cumulative business risk", chain.cumulative_risk);
    appendList(impact, "Capabilities gained", (chain.cumulative_capabilities || []).map(displayStatus));
    appendList(impact, "Potential business impact", chain.potential_business_impact);
    appendLabeledText(impact, "Rating notice", chain.notice);
    card.append(flow, impact);
    list.append(card);
  });
  if (!presentedChains.length) {
    chains.forEach((chain) => {
      const card = document.createElement("article");
      card.className = "chain-card";
      const title = document.createElement("strong");
      title.textContent = chain.chain_id || chain.id || "Attack path";
      const note = document.createElement("p");
      note.textContent = "Human-readable attack-flow detail is unavailable for this persisted response.";
      card.append(title, note);
      list.append(card);
    });
  }
}

function renderResults(data, modeLabel) {
  renderSummary(data);
  renderFindings(data);
  renderAgentActivity(data);
  renderChains(data);
  $("#result-mode").className =
    `status-pill ${statusClass(data.status || data.overall_status)}`;
  $("#result-mode").textContent = modeLabel;
  const resultTarget = data.target_url || data.origin || data.target || "";
  $("#result-target").textContent = [resultTarget, data.scan_id]
    .filter(Boolean).join(" · ");
  $("#raw-json").textContent = JSON.stringify(data, null, 2);
  $("#results").hidden = false;
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function targetContext(value) {
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    const loopback = host === "localhost"
      || host === "127.0.0.1"
      || host === "::1";
    return loopback
      ? { label: "Local controlled target", detail: "Loopback scope · DNS ownership proof not required", tone: "local" }
      : { label: "External target", detail: "HTTPS and exact-origin DNS ownership proof required", tone: "external" };
  } catch (_error) {
    return { label: "Target pending", detail: "Enter a complete HTTP or HTTPS origin", tone: "unknown" };
  }
}

function renderTargetContext(inputSelector, outputSelector) {
  const context = targetContext($(inputSelector).value);
  const output = $(outputSelector);
  output.className = `target-context ${context.tone}`;
  output.replaceChildren();
  const label = document.createElement("strong");
  label.textContent = context.label;
  const detail = document.createElement("span");
  detail.textContent = context.detail;
  output.append(label, detail);
}

function setButtonLoading(button, loading, idleText, busyText) {
  button.disabled = loading;
  button.textContent = loading ? busyText : idleText;
}

function populateScenarios() {
  scenarios.forEach((scenario) => {
    const option = document.createElement("option");
    option.value = scenario.id;
    option.textContent = scenario.label;
    $("#scenario").append(option);
  });
}

function setDevelopmentDnsBypassAvailability(enabled) {
  const control = $("#dev-dns-bypass-control");
  const checkbox = $("#skip-dns-verification");
  const warning = $("#dev-dns-bypass-warning");
  checkbox.checked = false;
  checkbox.disabled = !enabled;
  control.hidden = !enabled;
  warning.hidden = true;
}

async function configureDevelopmentDnsBypass() {
  setDevelopmentDnsBypassAvailability(false);
  try {
    const config = await requestJson("/api/test-harness/config");
    setDevelopmentDnsBypassAvailability(
      config.development_dns_bypass_enabled === true,
    );
  } catch (_error) {
    setDevelopmentDnsBypassAvailability(false);
  }
}

function initializeProgress() {
  const list = $("#progress-stages");
  list.replaceChildren();
  progressStages.forEach((stage) => {
    const item = document.createElement("li");
    item.dataset.state = "queued";
    const label = document.createElement("span");
    label.textContent = stage;
    const state = document.createElement("small");
    state.textContent = "queued";
    item.append(label, state);
    list.append(item);
  });
}

function setProgress(state) {
  const overall = $("#overall-progress");
  overall.className = `status-pill ${statusClass(state)}`;
  overall.textContent = displayStatus(state);
  $("#progress-stages").querySelectorAll("li").forEach((item) => {
    item.dataset.state = state === "running" ? "queued" : state;
    item.querySelector("small").textContent = state === "running" ? "queued" : state;
  });
}

async function refreshHealth() {
  const container = $("#health-components");
  container.replaceChildren();
  try {
    const health = await requestJson("/api/readiness");
    Object.entries(health.components || {}).forEach(([name, component]) => {
      const item = document.createElement("div");
      item.className = "health-item";
      const dot = document.createElement("span");
      dot.className = `health-dot ${statusClass(component.status)}`;
      const text = document.createElement("span");
      const label = document.createElement("strong");
      label.textContent = name === "postgresql"
        ? "PostgreSQL"
        : name[0].toUpperCase() + name.slice(1);
      const state = document.createElement("small");
      state.textContent = displayStatus(component.status);
      text.append(label, state);
      item.append(dot, text);
      container.append(item);
    });
  } catch (error) {
    const item = document.createElement("div");
    item.className = "health-item";
    const dot = document.createElement("span");
    dot.className = "health-dot danger";
    const text = document.createElement("span");
    text.textContent = error instanceof Error ? error.message : "Health check unavailable";
    item.append(dot, text);
    container.append(item);
  }
}

function activateTab(panelId) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === panelId;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.hidden = panel.id !== panelId;
  });
}

async function loadPersistedScan(scanId) {
  const encoded = encodeURIComponent(scanId);
  const [scan, findings, chains] = await Promise.all([
    requestJson(`/api/scans/${encoded}`),
    requestJson(`/api/scans/${encoded}/findings`),
    requestJson(`/api/scans/${encoded}/chains`),
  ]);
  return {
    scan_id: scan.id,
    status: scan.status,
    target_url: scan.target_url,
    findings,
    validations: findings.map((finding) => finding.validations?.at(-1) || {}),
    chains,
  };
}

let activeVerificationId = null;

function renderTargetVerification(verification) {
  activeVerificationId = verification.id || null;
  const panel = $("#verification-panel");
  const status = $("#verification-status");
  status.className = `status-pill ${statusClass(verification.status)}`;
  status.textContent = displayStatus(verification.status);
  $("#verification-message").textContent = verification.message || "";
  $("#verification-origin").textContent = verification.canonical_origin || "—";
  $("#verification-name").textContent = verification.txt_record_name || "—";
  $("#verification-value").textContent = verification.txt_record_value || "No longer required";
  $("#verification-expiry").textContent = verification.expires_at
    ? new Date(verification.expires_at).toLocaleString()
    : "—";
  const verified = verification.status === "verified";
  const expired = verification.status === "expired";
  $("#verify-dns-button").hidden = verified || expired;
  $("#regenerate-verification-button").hidden = !expired;
  if (verified) {
    $("#scan-button").textContent = "START VERIFIED ASSESSMENT";
  }
  panel.hidden = false;
}

async function createTargetVerification() {
  const verification = await postJson("/api/target-verifications", {
    target_url: $("#scan-target").value,
  });
  renderTargetVerification(verification);
  return verification;
}

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#scan-button");
  const message = $("#scan-message");
  $("#results").hidden = true;
  $("#progress-section").hidden = false;
  initializeProgress();
  setProgress("running");
  message.className = "status-message";
  message.textContent = "Scan running. Waiting for the synchronous backend pipeline…";
  setButtonLoading(button, true, "START ASSESSMENT", "ASSESSING…");
  try {
    const data = await postJson("/api/scans/run", {
      target_url: $("#scan-target").value,
      authorized: $("#scan-authorized").checked,
    });
    setProgress("completed");
    renderResults(data, "Real scan");
    $("#scan-id").value = data.scan_id || "";
    message.textContent = `Scan ${data.scan_id || ""} completed and persisted.`;
    refreshHealth();
  } catch (error) {
    setProgress("failed");
    message.className = "status-message error";
    if (error?.code === "target_verification_required") {
      $("#progress-section").hidden = true;
      try {
        await createTargetVerification();
        message.className = "status-message";
        message.textContent = "Add the DNS TXT record shown below, then select Verify DNS.";
      } catch (verificationError) {
        message.textContent = verificationError instanceof Error
          ? verificationError.message
          : "Could not create a DNS verification challenge.";
      }
    } else {
      message.textContent = error instanceof Error ? error.message : "Scan failed.";
    }
  } finally {
    setButtonLoading(button, false, "START ASSESSMENT", "ASSESSING…");
  }
});

$("#verify-dns-button").addEventListener("click", async () => {
  const button = $("#verify-dns-button");
  const message = $("#scan-message");
  if (!activeVerificationId) return;
  setButtonLoading(button, true, "VERIFY DNS", "VERIFYING…");
  try {
    const verification = await postJson(
      `/api/target-verifications/${encodeURIComponent(activeVerificationId)}/verify`,
      {},
    );
    renderTargetVerification(verification);
    message.className = verification.status === "verified"
      ? "status-message"
      : "status-message error";
    message.textContent = verification.status === "verified"
      ? "Domain verified. You can now run the security scan."
      : verification.message;
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "DNS verification failed.";
  } finally {
    setButtonLoading(button, false, "VERIFY DNS", "VERIFYING…");
  }
});

$("#regenerate-verification-button").addEventListener("click", async () => {
  const message = $("#scan-message");
  try {
    const verification = await createTargetVerification();
    message.className = "status-message";
    message.textContent = verification.message;
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "Could not create a new challenge.";
  }
});

$("#scan-target").addEventListener("input", () => {
  activeVerificationId = null;
  $("#verification-panel").hidden = true;
  $("#scan-button").textContent = "START ASSESSMENT";
  renderTargetContext("#scan-target", "#scan-target-context");
});

$("#demo-target").addEventListener("input", () => {
  renderTargetContext("#demo-target", "#demo-target-context");
});

$("#demo-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#demo-button");
  const message = $("#demo-message");
  $("#results").hidden = true;
  message.className = "status-message";
  message.textContent = "Running controlled deterministic validation…";
  setButtonLoading(button, true, "RUN CONTROLLED DEMO", "RUNNING…");
  try {
    const data = await postJson("/api/test-harness/run", {
      target_url: $("#demo-target").value,
      scenario: $("#scenario").value,
      authorized: $("#demo-authorized").checked,
      skip_dns_verification: $("#skip-dns-verification").checked,
    });
    const modeLabel = data.development_dns_bypass_used
      ? "Controlled Demo · DEVELOPMENT DNS BYPASS"
      : "Controlled Lab Demonstration";
    renderResults(data, modeLabel);
    $("#scan-id").value = data.scan_id || "";
    message.textContent = "Controlled lab pipeline completed.";
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "Controlled demo failed.";
  } finally {
    setButtonLoading(button, false, "RUN CONTROLLED DEMO", "RUNNING…");
  }
});

$("#skip-dns-verification").addEventListener("change", (event) => {
  $("#dev-dns-bypass-warning").hidden = !event.target.checked;
});

$("#lookup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#lookup-button");
  const message = $("#lookup-message");
  message.className = "status-message";
  message.textContent = "Loading persisted scan…";
  setButtonLoading(button, true, "LOAD SCAN", "LOADING…");
  try {
    const data = await loadPersistedScan($("#scan-id").value.trim());
    renderResults(data, "Persisted scan");
    message.textContent = `Loaded ${data.scan_id}.`;
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "Could not load scan.";
  } finally {
    setButtonLoading(button, false, "LOAD SCAN", "LOADING…");
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});
$("#refresh-health").addEventListener("click", refreshHealth);

populateScenarios();
initializeProgress();
renderTargetContext("#scan-target", "#scan-target-context");
renderTargetContext("#demo-target", "#demo-target-context");
refreshHealth();
configureDevelopmentDnsBypass();
