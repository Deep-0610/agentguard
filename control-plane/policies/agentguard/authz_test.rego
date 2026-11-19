package agentguard.authz

import rego.v1

test_default_deny_for_unknown_action if {
	result := decision with input as {
		"action": "unknown",
		"actor": {"tenant_id": "tenant-a", "role": "viewer"},
		"resource": {"tenant_id": "tenant-a"}
	}
	result.effect == "deny"
}

test_inventory_read_allowed_for_tenant_member if {
	result := decision with input as {
		"action": "inventory.read",
		"actor": {"tenant_id": "tenant-a", "role": "analyst"},
		"resource": {"tenant_id": "tenant-a"}
	}
	result.effect == "allow"
}

test_tool_schema_drift_denied if {
	result := decision with input as {
		"action": "tool.invoke",
		"actor": {"tenant_id": "tenant-a", "role": "analyst"},
		"resource": {"tenant_id": "tenant-a"},
		"tool": {"risk": "low", "schema_hash": "new", "approved_schema_hash": "approved"}
	}
	result.effect == "deny"
}

test_high_impact_requires_approval if {
	result := decision with input as {
		"action": "tool.invoke",
		"actor": {"tenant_id": "tenant-a", "role": "analyst"},
		"resource": {"tenant_id": "tenant-a"},
		"tool": {"risk": "critical", "schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approved_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"approval": {"required": true}
	}
	result.effect == "approval_required"
}

test_tenant_mismatch_denied if {
	result := decision with input as {
		"action": "inventory.read",
		"actor": {"tenant_id": "tenant-a", "role": "admin"},
		"resource": {"tenant_id": "tenant-b"}
	}
	result.effect == "deny"
}

test_low_risk_matching_tool_allowed if {
	result := decision with input as {
		"action": "tool.invoke",
		"actor": {"tenant_id": "tenant-a", "role": "analyst"},
		"resource": {"tenant_id": "tenant-a"},
		"tool": {"risk": "low", "schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approved_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}
	result.effect == "allow"
}

test_medium_risk_requires_approval if {
	result := decision with input as {
		"action": "tool.invoke",
		"actor": {"tenant_id": "tenant-a", "role": "analyst"},
		"resource": {"tenant_id": "tenant-a"},
		"tool": {"risk": "medium", "schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "approved_schema_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"approval": {"required": true}
	}
	result.effect == "approval_required"
}
