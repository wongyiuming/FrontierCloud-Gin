# Project instructions

Read `ARCHITECTURE.md` and `CONTRIBUTING.md` before changing cross-cutting behavior.
Their architecture and contribution constraints apply throughout this repository.

## Frontend baseline

- All frontend work MUST use HTML, CSS and native JavaScript.
- Use native DOM, CSS, Canvas, SVG and browser Web APIs for UI and animation.
- Do not introduce frontend frameworks, framework runtimes, JSX/TSX,
  framework-specific components or framework-based UI systems. This includes
  React, Vue, Angular, Svelte, Solid, Next.js and Nuxt.
- Do not replace native rendering with an engine such as Three.js.
- Build-only and test-only tools may serve their existing roles, but must not
  bring a frontend framework into shipped browser code.
- Apply this baseline to public pages, players, Admin GUI and all future UI
  changes. The authoritative policy is the frontend baseline in `ARCHITECTURE.md`.
