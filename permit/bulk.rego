package permit.bulk

import future.keywords

# Batch PDP: each entry mirrors the full document at POST /v1/data/permit/root for that query
# (allow, allowing_sources, debug when enabled, etc.).
#
# Input:
#   user: { "key": "<user id>" }
#   context: {}  # optional; forwarded to each evaluation
#   queries: [
#     { "action": "<action>", "resource": { "type": "...", "tenant": "...", "key": "..." } },
#     ...
#   ]
#
# Output document:
#   results: [ { "allow": ..., "allowing_sources": ..., "debug": ... }, ... ]  # same order as queries
#   decisions: [ true, false, ... ]  # convenience: each results[i].allow (legacy clients)

results := [doc |
	some i
	q := qs[i]
	doc := root_doc(q)
] {
	qs := safe_queries
}

safe_queries := q {
	q := object.get(input, "queries", [])
	is_array(q)
} else := []

root_doc(q) := doc {
	inp := {
		"user": input.user,
		"action": q.action,
		"resource": q.resource,
		"context": object.get(input, "context", {}),
	}
	doc := data.permit.root with input as inp
}

decisions := [r.allow |
	some i
	r := results[i]
]
