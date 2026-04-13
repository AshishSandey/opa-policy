package permit.bulk

import future.keywords

# Batch PDP: same semantics as N calls to POST /v1/data/permit/root with shared user (and optional context).
#
# Input:
#   user: { "key": "<user id>" }
#   context: {}  # optional; forwarded to each evaluation
#   queries: [
#     { "action": "<action>", "resource": { "type": "...", "tenant": "...", "key": "..." } },
#     ...
#   ]
#   (resource.key is optional when not scoping to an instance.)
#
# Output document:
#   decisions: [ true, false, ... ]  # same order and length as queries

decisions := [allowed |
	some i
	q := qs[i]
	allowed := eval_one(q)
] {
	qs := safe_queries
}

safe_queries := q {
	q := object.get(input, "queries", [])
	is_array(q)
} else := []

eval_one(q) := allowed {
	inp := {
		"user": input.user,
		"action": q.action,
		"resource": q.resource,
		"context": object.get(input, "context", {}),
	}
	allowed := data.permit.root.allow with input as inp
}
