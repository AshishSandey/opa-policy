package system.authz

default allow = false                       # Reject requests by default.

allow {                                     # Allow request if...
    "permit_key_wqjHPYEa7QW90YZXvIPf4qHth5YeTwMmT9tNVMpANmoLKQia1dSI4apCRYjIQKm6BXKSH5yP1LqxjBc2ANJYSe" == input.identity  # Identity is the secret root key.
}

allow {
    input.path[0] == "health"
}

