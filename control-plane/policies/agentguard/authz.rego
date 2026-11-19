package agentguard.authz

import rego.v1

default decision := {
  "effect": "deny",
  "rule_id": "default-deny",
  "reason": "No policy explicitly allowed this action."
}

decision := {
  "effect": "deny",
  "rule_id": "tenant-boundary",
  "reason": "Actor and resource belong to different tenants."
} if {
  input.actor.tenant_id != input.resource.tenant_id
}

decision := {
  "effect": "allow",
  "rule_id": "inventory-read",
  "reason": "Authenticated tenant member may read tenant inventory."
} if {
  input.action == "inventory.read"
  input.actor.role in {"owner", "admin", "analyst", "viewer"}
  input.actor.tenant_id == input.resource.tenant_id
}

decision := {
  "effect": "deny",
  "rule_id": "tool-schema-drift",
  "reason": "Tool schema differs from the approved baseline."
} if {
  input.action == "tool.invoke"
  input.actor.tenant_id == input.resource.tenant_id
  input.tool.schema_hash != input.tool.approved_schema_hash
}

decision := {
  "effect": "approval_required",
  "rule_id": "high-impact-tool-approval",
  "reason": "High-impact tool calls require explicit human approval."
} if {
  input.action == "tool.invoke"
  input.actor.tenant_id == input.resource.tenant_id
  input.tool.risk in {"medium", "high", "critical"}
  regex.match("^[a-f0-9]{64}$", input.tool.schema_hash)
  regex.match("^[a-f0-9]{64}$", input.tool.approved_schema_hash)
  input.tool.schema_hash == input.tool.approved_schema_hash
  input.approval.required == true
}

decision := {
  "effect": "deny",
  "rule_id": "high-impact-approval-missing",
  "reason": "High-impact tool calls are denied when approval is not configured."
} if {
  input.action == "tool.invoke"
  input.actor.tenant_id == input.resource.tenant_id
  input.tool.risk in {"high", "critical"}
  regex.match("^[a-f0-9]{64}$", input.tool.schema_hash)
  regex.match("^[a-f0-9]{64}$", input.tool.approved_schema_hash)
  input.tool.schema_hash == input.tool.approved_schema_hash
  input.approval.required != true
}

decision := {
  "effect": "allow",
  "rule_id": "low-risk-tool",
  "reason": "Low-risk tool schema matches its approved baseline."
} if {
  input.action == "tool.invoke"
  input.actor.tenant_id == input.resource.tenant_id
  input.tool.risk == "low"
  regex.match("^[a-f0-9]{64}$", input.tool.schema_hash)
  regex.match("^[a-f0-9]{64}$", input.tool.approved_schema_hash)
  input.tool.schema_hash == input.tool.approved_schema_hash
}
