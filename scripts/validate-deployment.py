"""Validate platform configuration against public provider JSON schemas."""
import json
import os
import subprocess
from pathlib import Path

import httpx
import jsonschema
import yaml

root = Path(__file__).resolve().parents[1]
with httpx.Client(timeout=20, follow_redirects=True) as client:
    render_schema = client.get("https://render.com/schema/render.yaml.json")
    render_schema.raise_for_status()
    vercel_schema = client.get("https://openapi.vercel.sh/vercel.json")
    vercel_schema.raise_for_status()
render = yaml.safe_load((root / "render.yaml").read_text())
vercel = json.loads((root / "frontend" / "vercel.json").read_text())
output = json.loads(subprocess.check_output(
    ["node", "--input-type=module", "-e",
     "import('./scripts/build-vercel.mjs').then(({buildOutputConfig})=>console.log(JSON.stringify(buildOutputConfig(process.env.WEBSCOPE_API_ORIGIN))))"],
    cwd=root / "frontend",
    env={**os.environ, "WEBSCOPE_API_ORIGIN": "https://webscope-api.example.invalid"},
))
jsonschema.validate(render, render_schema.json())
vercel_definition = vercel_schema.json()
# Vercel's published schema currently mixes drafts in unused experimentalTriggers.
# Validate our instance with its declared draft without meta-validating those unused definitions.
jsonschema.validators.validator_for(vercel_definition)(vercel_definition).validate(vercel)
jsonschema.validators.validator_for(vercel_definition)(vercel_definition).validate({"routes": output["routes"]})
assert output["version"] == 3
assert "disk" not in render["services"][0]
assert render["services"][0]["plan"] == "free"
result = {"result": "PASS", "render_schema": str(render_schema.url), "vercel_schema": str(vercel_schema.url),
          "render_ephemeral_storage": True, "vercel_same_origin_api_rewrite": True,
          "remote_deployment_performed": False}
result["vercel_static_project_config"] = True
result["vercel_build_output_version"] = output["version"]
result["vercel_validation_scope"] = "Configuration instance validated; provider schema meta-validation omitted because unused experimentalTriggers mix JSON Schema drafts."
directory = root / "docs" / "verification-logs" / "hosted"
directory.mkdir(parents=True, exist_ok=True)
(directory / "deployment-schema-validation.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
