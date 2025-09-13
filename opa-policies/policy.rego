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
    # But exclude GitHub requests which have their own authorization logic
    input.request.host in data.allowed_domains
    input.request.method in ["GET", "HEAD"]
    not is_github_request
}

allow if {
    # GitHub-specific access control
    github_access_allowed
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


# GitHub access control logic
github_access_allowed if {
    # Check if this is a GitHub request
    is_github_request
    # Allow read operations for all GitHub repos (if enabled)
    github_read_operation
    data.github_read_access_enabled == true
}

github_access_allowed if {
    # Check if this is a GitHub request
    is_github_request
    # Allow write operations only for authorized users/repos
    github_write_operation
    github_write_authorized
}

# Helper function to detect GitHub requests
is_github_request if {
    input.request.host == "github.com"
}

is_github_request if {
    input.request.host == "api.github.com"
}

is_github_request if {
    endswith(input.request.host, ".githubusercontent.com")
}

# Detect Git read operations
github_read_operation if {
    input.request.method == "GET"
    contains(input.request.path, "/info/refs")
    contains(input.request.query, "service=git-upload-pack")
}

github_read_operation if {
    input.request.method == "POST"
    endswith(input.request.path, "/git-upload-pack")
}

github_read_operation if {
    # Allow general GET/HEAD requests to GitHub (for web interface, API, etc.)
    # But exclude Git write operation discovery requests
    input.request.method in ["GET", "HEAD"]
    not github_write_operation
}

# Detect Git write operations
github_write_operation if {
    input.request.method == "GET"
    contains(input.request.path, "/info/refs")
    contains(input.request.query, "service=git-receive-pack")
}

github_write_operation if {
    input.request.method == "POST"
    endswith(input.request.path, "/git-receive-pack")
}

# Check if write operation is authorized
github_write_authorized if {
    # Parse repository from path (format: /user/repo.git or /user/repo)
    github_repo := github_parse_repo(input.request.path)
    github_repo != null
    
    # Check if user has write access
    github_user_has_write_access(github_repo)
}

github_write_authorized if {
    # Parse repository from path
    github_repo := github_parse_repo(input.request.path)
    github_repo != null
    
    # Check if specific repo is allowed
    github_repo_has_write_access(github_repo)
}

# Extract user/repo from GitHub path
github_parse_repo(path) := repo if {
    # Handle paths like /user/repo.git or /user/repo
    path_parts := split(trim(path, "/"), "/")
    count(path_parts) >= 2
    user := path_parts[0]
    repo_with_git := path_parts[1]
    repo_name := trim_suffix(repo_with_git, ".git")
    repo := sprintf("%s/%s", [user, repo_name])
}

# Check if user has write access
github_user_has_write_access(repo) if {
    repo_parts := split(repo, "/")
    count(repo_parts) >= 2
    user := repo_parts[0]
    user in data.github_allowed_users
}

# Check if specific repository has write access
github_repo_has_write_access(repo) if {
    repo in data.github_allowed_repos
}

# Updated reason logic to handle GitHub-specific cases
reason := "Host not allowed" if {
    not host_is_known
    not is_github_request
}

reason := "Method not allowed for restricted domain" if {
    host_is_allowed
    not host_is_unrestricted
    not input.request.method in ["GET", "HEAD"]
    not is_github_request
}

reason := "GitHub write access denied - user not authorized" if {
    is_github_request
    github_write_operation
    not github_write_authorized
}

reason := "GitHub read access disabled by configuration" if {
    is_github_request
    github_read_operation
    data.github_read_access_enabled != true
    not github_write_operation
}

reason := "GitHub API access denied - only Git operations and GET/HEAD requests allowed" if {
    is_github_request
    not github_read_operation
    not github_write_operation
}

# Default reason - will be "Request allowed" for allowed requests,
# or specific denial reason for denied requests
default reason := "Request allowed"

# Return detailed decision
decision := {
    "allow": allow,
    "reason": reason
}