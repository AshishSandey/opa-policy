# Vanilla OPA replacement for Permit.io's permit_rebac built-in functions (ReBAC plugin).
# Derives role information from data.role_assignments and data.resource_instances only.
# Relationship graph traversal / derived roles from data.relationships are not replicated here;
# extend this module if you materialize derived assignments in data at sync time.

package permit.rebac_native

import future.keywords.in

# --- helpers ---

# Permit-style "Resource#Role" string; pass through if already contains "#".
format_role_string(resource_fq, role_name) := s {
	contains(role_name, "#")
	s := role_name
} else = s {
	s := sprintf("%s#%s", [resource_fq, role_name])
}

# Tenant for an instance; empty string if unknown (assignment is skipped for tenant filtering).
resource_tenant(resource_fq) := t {
	t := data.resource_instances[resource_fq].tenant
} else = "" {
	true
}

split_fq(res_fq) := [p[0], p[1]] {
	p := split(res_fq, ":")
	count(p) == 2
}

# Instance matches authorized_users query (type + optional instance key).
matches_resource_query(res_fq, resource) {
	p := split_fq(res_fq)
	p[0] == resource.type
	is_null(object.get(resource, "key", null))
} else {
	p := split_fq(res_fq)
	p[0] == resource.type
	p[1] == object.get(resource, "key", "")
}

# Whether an assignment string resolves to the given role_permissions key.
assignment_matches_role_key(role_key, res_fq, role_name) {
	role_name == role_key
} else {
	rs := format_role_string(res_fq, role_name)
	parts := split(rs, "#")
	count(parts) == 2
	parts[1] == role_key
}

# --- permit.rebac: roles for current decision (merged into scoped_users_obj) ---

# Returns same shape as permit_rebac.roles: { "roles": [...], "debugger": object }.
# Parameter cannot be named "input" (shadows the input document in Rego).
roles_result(inp) := {"roles": role_list, "debugger": dbg} {
	user := sprintf("user:%s", [inp.user.key])
	tenant := inp.resource.tenant
	assigns := object.get(data.role_assignments, user, {})
	role_list := [r |
		some res, role_names in assigns
		not startswith(res, "__tenant:")
		resource_tenant(res) == tenant
		rn := role_names[_]
		r := format_role_string(res, rn)
	]
	dbg := {}
}

# --- permit.user_permissions: map resource -> ["Resource#Role", ...] ---

all_roles(inp) := m {
	user := sprintf("user:%s", [inp.user.key])
	assigns := object.get(data.role_assignments, user, {})
	m := {res: arr |
		some res, role_names in assigns
		not startswith(res, "__tenant:")
		arr := [fmt | rn := role_names[_]; fmt := format_role_string(res, rn)]
	}
}

# --- permit.authorized_users: linked users for a resource query ---

# Shape: { "user:<id>": { "roles": { "<role_key>": [ {"role","resource"} ] }, "debugger": {} } }
linked_users(resource) := out {
	tenant := resource.tenant
	out := {uid: entry |
		some uid, assigns in data.role_assignments
		startswith(uid, "user:")
		entry := linked_user_entry(assigns, resource, tenant)
		count(object.keys(entry.roles)) > 0
	}
}

grants_for_role(assigns, resource, tenant, role_key) := gs {
	gs := [g |
		some res, role_names in assigns
		not startswith(res, "__tenant:")
		resource_tenant(res) == tenant
		matches_resource_query(res, resource)
		rn := role_names[_]
		assignment_matches_role_key(role_key, res, rn)
		g := {"role": role_key, "resource": res}
	]
}

linked_user_entry(assigns, resource, tenant) := {"roles": rmap, "debugger": {}} {
	perm := object.get(data.role_permissions, resource.type, {})
	rmap := {role_key: grants |
		some role_key
		perm[role_key]
		grants := grants_for_role(assigns, resource, tenant, role_key)
		count(grants) > 0
	}
}
