import base64
import io
import textwrap

from PIL import Image, ImageDraw, ImageFont

from app.services.store import evidence, event


def capture(db, source):
    """Render only already-redacted persisted text, never target HTML or scripts."""
    lines = [
        "WebScope | Redacted evidence capture",
        "Not a browser rendering of the target",
        f"Evidence: {source.id}",
        f"Type: {source.type}",
        f"Source: {source.source}",
        f"Collected: {source.created_at}",
        f"Integrity: {source.sha256}",
        "",
    ]
    raw = source.raw or str(source.data)
    for line in raw.splitlines():
        lines.extend(textwrap.wrap(line, width=104, replace_whitespace=False) or [""])
        if len(lines) > 76:
            lines = lines[:76] + ["[Capture truncated. Inspect the full source evidence in the workstation.]"]
            break
    image = Image.new("RGB", (1100, 50 + 21 * len(lines)), "#111923")
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default(size=15)
    for index, line in enumerate(lines):
        draw.text((24, 22 + index * 21), line.encode("ascii", "replace").decode(), fill="#dce7ef", font=font)
    output = io.BytesIO()
    image.save(output, format="PNG")
    item = evidence(
        db,
        source.assessment_id,
        "SCREENSHOT",
        f"webscope:evidence:{source.id}",
        "Rendered capture of redacted evidence (not target-browser rendering)",
        {
            "source_evidence_id": source.id,
            "media_type": "image/png",
            "width": image.width,
            "height": image.height,
            "image_base64": base64.b64encode(output.getvalue()).decode(),
            "rendering": "Redacted persisted text only",
        },
    )
    event(
        db,
        source.assessment_id,
        "EVIDENCE_CAPTURED",
        "Redacted evidence image captured",
        {"evidence_id": item.id},
    )
    return item
