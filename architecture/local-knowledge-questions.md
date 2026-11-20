# A13 — Evidence-grounded questions in the local workspace

A13 is a local synthetic-only development assignment, not an original roadmap work-package number or permission to enable the hosted service. It composes the existing workspace, versioned read API, A12 publication policy and deterministic lexical scorer.

## Read boundary

The fixture workspace is a separate Next application, bound to a numeric loopback address. Its same-origin bridge accepts only the canonical knowledge list, search, record and source GET paths. It verifies an existing Supabase SSR fixture session cookie using the fixed local fixture signer and forwards only the verified native bearer to a second loopback listener. There is no browser-facing token mint or refresh, tenant or node selector, upstream redirect, or cached evidence. The ordinary release proxy cannot select this listener.

The A13 FastAPI assembly has only the A12 published-reader and identity connections. It has no intake routes, worker connection, quarantine store, or maintenance endpoint. It independently verifies the bearer with the existing staged mock transport and resolves the current native BRI session. PostgreSQL rechecks active session, exact-node `knowledge:read`, approval, and both current record and exact-version allow decisions through the existing restricted `csv_read_published` function before the application can select evidence. Neither approval nor a matching question changes an allow decision. Record and source follow-through reauthorize on every fresh request. The normal release and legacy readers retain their existing behavior.

## Evidence and display

The question path scores literal text fragments from authorized CSV data cells with the existing lexical scorer. It does not return raw JSON as an answer, combine cells into a claim, or generate an explanation. The interface distinguishes supported, insufficient and conflicting evidence. An insufficient response has no answer or citations. A conflict has authorized citations and no selected answer. It does not detect semantic contradictions or infer supersession.

Citations identify the exact source version and extraction and carry two distinct SHA-256 digests: exact original bytes and the derived extraction. The inclusive physical line range is the enclosing A12 extraction range, not an asserted row or cell location. The matcher considers at most 1,024 eligible items, 2,000,000 serialized characters and 20,000 nonempty fragments. Excerpts are at most 512 characters, with no more than five citations. If limits prevent a complete decision, it abstains rather than returning partial support. Access-denied evidence is not counted or scored.

The local record list is a preview, not the complete corpus: it returns at most 100 authorized records and 1 MiB of serialized JSON, earliest proposal first with proposal ID as the tiebreaker. Preview text is at most 512 characters. The authorized detail path can still open a full valid A12 extraction, and search does not use the displayed list as its input. These output limits do not bound the database transfer: this fixture still loads the corpus through the existing reader before applying application limits.

The workspace clears prior evidence while a fresh read is pending and on denial. Leaving a page parks its evidence and disables reads; history restoration starts a new read rather than bringing back a previously displayed result. A committed revocation affects subsequent fresh reads; it does not recall text already delivered or push an update to an idle browser.

See [local fixture workspace](../web/local-workspace/README.md) for the separate listener and signer contract. This slice does not enable a hosted read or write path, use an external model, add an index or ingestion format, or decide production storage, scanning, retention or disposition.
