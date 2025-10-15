# Domains with restricted access (only GET/HEAD allowed)
allowed_domains:
{{- range .Values.opa.policy.allowedDomains }}
  - {{ . | quote }}
{{- end }}

# Domains with unrestricted access (all HTTP methods allowed)
unrestricted_domains:
{{- range .Values.opa.policy.unrestrictedDomains }}
  - {{ . | quote }}
{{- end }}

# GitHub access control configuration
github_read_access_enabled: {{ .Values.opa.policy.githubReadAccessEnabled }}

# GitHub users allowed to perform write operations
github_allowed_users:
{{- range .Values.opa.policy.githubAllowedUsers }}
  - {{ . | quote }}
{{- end }}

# Specific GitHub repositories allowed for write operations
github_allowed_repos:
{{- range .Values.opa.policy.githubAllowedRepos }}
  - {{ . | quote }}
{{- end }}

# AWS domains configuration
aws_access_enabled: {{ .Values.opa.policy.awsAccessEnabled | default false }}

aws_allowed_services:
{{- range .Values.opa.policy.awsAllowedServices }}
  - {{ . | quote }}
{{- end }}
