# rootcard specification

> **Status: stub.** Phase 1 of [docs/PLAN.md](../docs/PLAN.md) turns the design
> ([docs/DESIGN.md](../docs/DESIGN.md)) into a normative, application-neutral
> specification here. Until then, nothing in this file is normative except §0.

## 0. Conventions (normative)

- The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
- Format version: `1`.
- Every domain-separation label is `rootcard/<purpose>/v<version>`, for example `rootcard/id/v1`. A label is never reused for
  another purpose.
- `spec/vectors/*.json` are part of the specification. Every conforming implementation MUST reproduce them exactly.
  `meta.json` lists the format version, the label prefix and the labels.
