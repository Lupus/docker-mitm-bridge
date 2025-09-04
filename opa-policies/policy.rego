package mitmproxy.policy

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

# Main allow rule - evaluates to true if request should be allowed
allow if {
    # Check if host is in unrestricted domains (all methods allowed)
    input.request.host in data.unrestricted_domains
}

allow if {
    # Check if host is in allowed domains with GET/HEAD only
    input.request.host in data.allowed_domains
    input.request.method in ["GET", "HEAD"]
}

# Helper functions for decision reasoning
host_is_allowed if {
    input.request.host in data.allowed_domains
}

host_is_unrestricted if {
    input.request.host in data.unrestricted_domains
}

host_is_known if {
    host_is_allowed
}

host_is_known if {
    host_is_unrestricted
}

# Determine the reason for the decision
reason := "Host not allowed" if {
    not host_is_known
}

reason := "Method not allowed for restricted domain" if {
    host_is_allowed
    not host_is_unrestricted
    not input.request.method in ["GET", "HEAD"]
}

reason := "Request allowed" if {
    allow
}

# Return detailed decision
decision := {
    "allow": allow,
    "reason": reason
}