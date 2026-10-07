---
name: WebScope
description: A restrained, evidence-first analyst workstation.
colors:
  workspace: "#101419"
  panel: "#151b22"
  raised-panel: "#1b2430"
  sidebar: "#131920"
  text: "#e5eaf0"
  muted: "#a1afbf"
  divider: "#2c3744"
  subtle-divider: "#242e39"
  link: "#a8cefa"
  primary-fill: "#accff7"
  primary-ink: "#12263d"
  primary-hover: "#c0ddff"
  focus: "#b5d8ff"
  input: "#141c25"
  input-border: "#425065"
  selected-navigation: "#243345"
  selected-navigation-ink: "#c2ddfc"
  evidence: "#0c1117"
  evidence-ink: "#c0d0e1"
  rationale: "#1a2735"
  rationale-border: "#435972"
  severity-info: "#b9c4d1"
  severity-low: "#a5cbe1"
  severity-medium: "#edc47f"
  severity-high: "#efaa84"
  severity-critical: "#f3a7b3"
typography:
  headline:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "27px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-0.025em"
  title:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "17px"
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "12px"
    fontWeight: 550
  technical:
    fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace'
    fontSize: "11.5px"
    fontWeight: 400
    lineHeight: 1.7
rounded:
  tag: "3px"
  control: "4px"
  evidence-panel: "5px"
  dialog: "7px"
spacing:
  tight: "8px"
  control: "12px"
  group: "16px"
  section: "28px"
  desktop-gutter: "32px"
components:
  button-primary:
    backgroundColor: "{colors.primary-fill}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.control}"
    padding: "8px 13px"
    typography: "{typography.label}"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.primary-ink}"
  text-input:
    backgroundColor: "{colors.input}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "9px 11px"
  selected-navigation:
    backgroundColor: "{colors.selected-navigation}"
    textColor: "{colors.selected-navigation-ink}"
    rounded: "{rounded.control}"
    padding: "9px 12px"
  evidence-block:
    backgroundColor: "{colors.evidence}"
    textColor: "{colors.evidence-ink}"
    rounded: "{rounded.control}"
    padding: "17px"
    typography: "{typography.technical}"
---

# Design System: WebScope

## Overview

**Creative North Star: "The evidence bench"**

WebScope uses a graphite working surface for sustained technical investigation.
The visual hierarchy follows the analyst's task: establish context, inspect
observations, then record a judgment. It is deliberately a workstation rather
than a marketing dashboard.

This system is extracted from the built implementation in
`frontend/src/styles.css`, its Tailwind theme, and the shared React components.
The supplied brief fixes its restrained dark direction. It uses system fonts,
flat section divisions, technical tables, and a limited action accent.

**Key Characteristics:**
- Persistent assessment context and compact navigation.
- Evidence and provenance close to the observation they support.
- Separate presentation of automated facts and analyst decisions.
- Dense tables with local scrolling, not page-wide overflow.

## Colors

Cool graphite neutrals carry the interface; pale blue identifies navigation,
source links, selection, and intentional actions.

### Primary

The link accent is separate from the slightly lighter primary-button fill.
Primary buttons use dark ink; linked source records use the light accent.
The focus color identifies keyboard position, not decoration.

### Neutral

The workspace is the darkest broad surface. Sidebar, input, and raised-panel
colors distinguish functional regions without card shadows. Dividers organize
content at section and row boundaries. Muted text remains visible against the
working surface; it is used for timestamps, hints, and provenance.

### Semantic

Five severity colors are paired with explicit text labels. Informational and
low observations stay cool; medium is amber, high is orange, and critical is
rose. Review status and confidence use neutral chips, not severity coloring.

**The Separate Signals Rule.** Severity color must not imply confidence or an
analyst-confirmed issue.

## Typography

System sans-serif is used for navigation, task controls, prose, and headings.
System monospace is reserved for URLs, hashes, IDs, methods, headers, and raw
or structured evidence.

Headlines are compact rather than display-sized. Section titles step down to
the title role, body text to the body role, and tables to compact 12px text.
Page headlines reduce to 25px on smaller layouts. Technical blocks use the
technical role and preserve whitespace while allowing long values to wrap.
General prose is bounded to 78 characters; explanatory empty states are
narrower.

**The Technical Values Rule.** Monospace identifies a value to inspect or
copy, never merely a security-themed aesthetic.

## Layout

The desktop frame has a fixed, vertically scrollable 232px sidebar, a 58px
context bar, and a flexible content area with 32px horizontal gutters. Main
content stops growing at 1710px. At 1150px, the sidebar contracts to 212px
and gutters to 23px.

At 800px, navigation becomes an explicitly opened drawer below a 58px mobile
header. The closed drawer is hidden from keyboard navigation; while open,
underlying content is inert. At 560px, gutters reduce to 16px, forms stack,
and primary header actions receive full available width.

Forms use two columns, or three for compact policy fields. Data tables scroll
inside their own region and retain readable columns on narrow screens.
Finding review uses a main evidence column and a 330px analyst column; at
1150px the review areas move below, and at 560px they stack completely.

Section spacing is larger above the title than between the title and content.
Summaries are compact horizontal inventories, not oversized hero metrics.

## Elevation & Depth

Most depth comes from tonal separation and one-pixel borders. Standard
sections and tables do not float above the workspace.

The confirmation dialog uses `0 20px 70px rgba(0,0,0,.5)` to establish a
genuine modal interruption. Graph nodes use
`0 3px 10px rgba(0,0,0,.2)` to remain legible over edges. These are structural
shadows, not glows.

Motion is limited to an activity spinner. Reduced-motion preference disables
it; text still communicates progress.

## Shapes

Small corners distinguish controls without making the workspace soft:
compact tags, four-pixel controls, five-pixel graph and explanation panels,
and a seven-pixel dialog. Tables, sections, and the context bar remain flat.
Circular marks are reserved for connection status and timeline events.

## Components

### Buttons and fields

Primary actions have pale blue fill and dark text. Secondary buttons have a
dark raised fill and visible border. Destructive actions use a restrained
rose treatment and require a confirmation dialog. Hover changes fill and
border; focus uses a two-pixel outline offset by three pixels, reduced to
one pixel around fields. Disabled controls reduce opacity and keep their
labels.

Inputs use a visible border, dark fill, and persistent labels. Helper text is
adjacent to the field. Success and failure states use text and an icon, never
color alone. Form contents remain present after a failed save.

Disabled collection actions retain a nearby reason: target validation,
authorization, passive mode, or missing explicit safe paths. Changed scope
or private-network permission reveals a separate reauthorization checkbox.
Archived and running assessments show a read-only notice rather than
silently accepting unavailable edits; saved report downloads remain usable.
Final finding dispositions require a written conclusion, and case selectors
offer only the current stage and valid lifecycle transitions.

### Navigation and tables

Selected navigation has a blue-gray fill and brighter text. Assessment
navigation remains available from linked evidence, transaction, finding,
and case details. A skip link moves directly to the main working area.

Tables expose search, actual record counts, and sortable headers where
appropriate. Source-record links remain explicit; rows do not become
ambiguous oversized click targets. Larger result sets reveal 50 more records
at a time.

### Evidence and explanation

The defining explanation panel is titled **Why WebScope flagged this**.
Its tonal emphasis precedes the evidence and review columns; its source link
is part of the panel, not hidden in metadata.

Raw and structured views use a real keyboard-operated tab pattern.
Preformatted blocks scroll locally and render untrusted content as text.
Truncated captures display an explicit warning. The analyst panel, neutral
confidence chip, and immutable facts strip prevent automated observations
from looking like final conclusions.

Persisted-text image captures use a keyboard-scrollable PNG figure with the
explicit caption **Redacted evidence capture · not a target-browser
screenshot**. The capture action never opens the target. Image bytes are
excluded from the structured metadata panel; source and derived evidence
IDs remain clickable in the lineage table. The figure reuses the title,
divider, and dark evidence-surface styles rather than introducing a separate
visual treatment.

### Graph and confirmations

The attack surface is a React Flow canvas with linked evidence nodes, labeled
relationships, zoom controls, fit view, and a minimap. A tabular observation
index provides an alternate route to source evidence.

Dialogs are reserved for collection confirmation and irreversible deletion.
Inventory entry, OpenAPI import, case editing, and analyst review remain
inline so their surrounding context is visible.

## Do's and Don'ts

### Do:
- **Do** keep source evidence reachable from observations and decisions.
- **Do** separate severity, confidence, review status, and priority.
- **Do** use the shared control, table, field, and status components.
- **Do** preserve readable columns with local table scrolling on mobile.
- **Do** describe empty, loading, failed, and truncated states explicitly.

### Don't:
- **Don't** invent assessment data, counters, intelligence, or results.
- **Don't** use severity color as a substitute for an analyst conclusion.
- **Don't** render target content as executable HTML.
- **Don't** turn ordinary sections into decorative cards or glowing panels.
- **Don't** hide collection authorization behind an automatic interaction.
