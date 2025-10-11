# Envoy Access Log Not Working

## Issue Summary

Envoy access logs are configured in the xDS service but are not appearing in the container logs. OPA decision logs prove that requests are being processed successfully, but no corresponding access log entries are written.

## Evidence

### 1. Access Logging IS Configured

Location: `cilium-tls-poc/xds-service/main.go:417-447`

```go
func buildAccessLog() ([]*accesslog.AccessLog, error) {
	// Create file access log config for stdout
	fileAccessLog := &file_accesslog.FileAccessLog{
		Path: "/dev/stdout",
		AccessLogFormat: &file_accesslog.FileAccessLog_LogFormat{
			LogFormat: &core.SubstitutionFormatString{
				Format: &core.SubstitutionFormatString_TextFormatSource{
					TextFormatSource: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: "[%START_TIME%] \"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%\" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% \"%REQ(X-FORWARDED-FOR)%\" \"%REQ(USER-AGENT)%\" \"%REQ(:AUTHORITY)%\" \"%UPSTREAM_HOST%\" \"ext_authz:%DYNAMIC_METADATA(envoy.filters.http.ext_authz:ext_authz_duration)%\"\n",
						},
					},
				},
			},
		},
	}
	// ... returns AccessLog array
}
```

### 2. Access Logs Added to All HTTP Connection Managers

The `buildAccessLog()` function is called 3 times:
- Line 501: HTTP listener (port 15001)
- Line 653: HTTPS listener with whitelisted domains (port 15002)
- Line 812: HTTPS fallback filter chain for blocked domains (port 15002)

Each call adds access logs to the respective HttpConnectionManager:
```go
httpManager := &hcm.HttpConnectionManager{
	CodecType:  hcm.HttpConnectionManager_AUTO,
	StatPrefix: "ingress_http_plain",
	AccessLog:  accessLogs,  // ← Added here
	// ...
}
```

### 3. OPA Logs Confirm Requests Are Processed

From CI run 18426751887, OPA decision logs show requests being processed:

```json
{
  "decision_id": "c3a998af-eaa9-4545-88a0-1ee5fd2dfd7f",
  "input": {
    "attributes": {
      "destination": {"address": {"socketAddress": {"address": "127.0.0.1", "portValue": 15001}}},
      "request": {
        "http": {
          "host": "google.com",
          "method": "GET",
          "path": "/"
        }
      }
    }
  },
  "result": false,
  "time": "2025-10-11T08:15:08Z"
}
```

This proves:
- Requests reach Envoy
- Envoy processes them through the HTTP connection manager
- ext_authz filter calls OPA
- OPA makes decisions
- HTTP responses must be generated

### 4. But NO Access Logs Appear

From the same CI run, checking Envoy logs:
```
--- Envoy Logs ---
[2025-10-11 08:15:16.624][1][info][upstream] [source/common/upstream/cds_api_helper.cc:32] cds: add 2 cluster(s), remove 1 cluster(s)
[2025-10-11 08:15:16.624][1][info][upstream] [source/common/upstream/cds_api_helper.cc:71] cds: added/updated 0 cluster(s), skipped 2 unmodified cluster(s)
...
```

Only INFO-level logs about cluster updates appear. No access log entries matching the format:
```
[START_TIME] "METHOD PATH PROTOCOL" RESPONSE_CODE ...
```

## Possible Causes

1. **Format String Error**: The access log format includes `DYNAMIC_METADATA(envoy.filters.http.ext_authz:ext_authz_duration)` which might have syntax issues
2. **xDS Configuration Not Applied**: The access log configuration might not be correctly marshaled/sent via xDS
3. **Envoy Version Issue**: The Envoy version (v1.28) might handle access logs differently
4. **Listener vs Connection Manager**: Access logs on connection managers might need additional listener-level config

## Recommended Investigation Steps

1. **Simplify Format String**: Remove the DYNAMIC_METADATA part to test if that's causing issues
2. **Add Debug Logging**: Add logs in xDS service to confirm access log config is being sent
3. **Check Envoy Config Dump**: Use `/config_dump` endpoint to verify access log config is received
4. **Test with Minimal Format**: Try simplest possible format: `"%REQ(:METHOD)% %REQ(:PATH)% %RESPONSE_CODE%\n"`
5. **Check Envoy Documentation**: Verify FileAccessLog proto usage for Envoy v1.28

## Workaround

OPA decision logs provide sufficient information for debugging policy decisions. The missing access logs are inconvenient but not blocking, as:
- OPA logs show all ext_authz decisions with full request details
- Test assertions check HTTP response codes via curl
- Envoy health checks confirm the proxy is functional

## Impact

**Low Priority** - Access logs would be helpful for debugging but are not critical:
- ✅ Security policy enforcement works (proven by OPA logs)
- ✅ Tests can verify behavior (via curl exit codes and output)
- ✅ Debugging is possible (via OPA decision logs)
- ❌ Missing detailed timing/performance data
- ❌ Cannot easily correlate requests across components

## Next Steps

This should be investigated after the current security fixes are merged and CI is green.
