# Integration Contract

Every investigation has a stable `INV-*` ID and source SHA-256.

Module result states use `SUCCESS`, `NO_DATA`, `NOT_CONFIGURED`, `NOT_CHECKED`, `FAILED`, `SKIPPED`, `TIMEOUT`, `SOURCE_ERROR`, `RATE_LIMITED`.

Downstream modules consume upstream structured data. They must not fabricate missing evidence. Threat findings reference evidence IDs generated in the same analysis package.

The unified response preserves:
`email`, `headers`, `authentication`, `routing`, `indicators`, `intelligence`, `assessment`, `findings`, `evidence`, `recommendations`, `report`, `modules`, `processingTimeline`, and `security`.
