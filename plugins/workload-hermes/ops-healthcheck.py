#!/usr/bin/env python3
import json
import sys
import urllib.request


def fail(message: str) -> None:
    print(f"ops-healthcheck: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    with urllib.request.urlopen("http://127.0.0.1:9119/api/status", timeout=5) as response:
        if response.status != 200:
            fail(f"status endpoint returned HTTP {response.status}")
        payload = json.load(response)
except (OSError, ValueError) as error:
    fail(f"status endpoint failed: {error}")

if not isinstance(payload, dict):
    fail("status endpoint returned a non-object payload")
if payload.get("auth_required") is not True:
    fail("dashboard authentication is not required")
providers = payload.get("auth_providers")
if not isinstance(providers, list) or "basic" not in providers:
    fail("dashboard basic authentication is not enabled")
if payload.get("gateway_running") is not True or payload.get("gateway_state") != "running":
    fail("gateway is not running")
platforms = payload.get("gateway_platforms")
if not isinstance(platforms, dict) or platforms:
    fail("gateway must have zero platform connectors")

print("ops-healthcheck: ok")
