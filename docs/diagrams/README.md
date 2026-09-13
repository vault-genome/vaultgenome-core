# Architecture diagrams (SVG)

Hand-rolled SVG architecture diagrams for use in ADRs, customer
reference designs, threat-model documents, and the investor-demo
website.

## Diagrams

| File                                                | Used by                                                     | Description                                              |
|-----------------------------------------------------|-------------------------------------------------------------|----------------------------------------------------------|
| [`architecture-overview.svg`](architecture-overview.svg) | Homepage hero, [ADR-0001](../adr/0001-frozen-producer-verifier-sealer-interface.md) | Operator → vault → 5 TEE backends → worker pool          |
| [`session-flow.svg`](session-flow.svg)              | [Reference design 02](../reference-designs/02-healthcare-clinical-decision.md), session-lifecycle docs | 13-step per-session flow with audit emission lanes        |

## Why SVG by hand, not Mermaid / PlantUML / draw.io

- **Stable rendering**: SVG that ships in the repo renders identically
  in every Markdown viewer (GitHub, GitLab, MkDocs, the investor-demo
  site, PDF exports). Tool-rendered diagrams drift when the tool
  updates; we have ~20 places these diagrams appear and one render
  artefact would visibly diverge from the others.
- **Diff-friendly**: SVG XML is text. PR review can comment on the
  exact element that changed.
- **No build dependency**: no Mermaid plug-in, no Java for PlantUML,
  no draw.io export step. The diagrams ship as-is.

## Authoring conventions

- **Viewport**: pick a sensible viewBox; 1100×600 to 1100×800 fits
  readability + GitHub PR diff width.
- **Fonts**: use `ui-monospace, SF Mono, Menlo, monospace` so the
  rendered text matches the project's monospace branding without
  requiring a custom web font.
- **Colours**: limit the palette to the website's CSS variables —
  `#0a0e14` background, `#7ad3ff` accent, `#1f8f5b` TEE green,
  `#c14f4f` failure red. Extending the palette requires PR review.
- **No gradients on text**: gradients only on container fills.
- **Arrows**: use `<marker>` defs at the top so the arrowhead is
  consistent across diagrams.

## Updating an SVG

1. Open the `.svg` file in a text editor.
2. Edit by hand. The viewBox and grid sizes make this surprisingly
   tractable — coordinates tend to align on multiples of 5 or 10.
3. Open in a browser to preview (`file://path/to/architecture-overview.svg`).
4. Commit the diff. Reviewers can comment on the exact `<text>` /
   `<rect>` element.

For larger redesigns, draw on paper first; the SVG should be the
last step, not the first.

## Embedding in Markdown

```markdown
![Architecture overview](docs/diagrams/architecture-overview.svg)
```

Width control via `<img>` tag if needed:

```html
<img src="docs/diagrams/architecture-overview.svg" alt="..." width="900">
```

## Embedding on the investor-demo site

```tsx
import architectureSvg from "@/../public/diagrams/architecture-overview.svg";

<Image src={architectureSvg} alt="..." width={900} height={500} />
```

(Note: copying the SVG to `investor-demo/web/public/diagrams/` is
preferable to importing across the repo boundary; the `core/docs/`
copy is the source of truth.)
