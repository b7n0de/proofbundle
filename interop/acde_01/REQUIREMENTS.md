# Requirements of draft-abak-agent-control-delivery-evidence-01

Every sentence of the draft that carries a BCP 14 key word in upper case, outside Section 1.2. Line numbers refer to the plain-text copy with SHA-256 `2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf` (2576 lines). Generated from `requirements.json` and `requirements_map.json`.

| id | section | lines | key words | requirement (quoted) | category |
|---|---|---|---|---|---|
| S4-1 | 4 | 529-531 | MAY | An implementation MAY carry the required facts in one artifact, in several artifacts, in protocol fields, in telemetry, or through external references. | not_implemented |
| S4.3-1 | 4.3 | 586-589 | MUST NOT | It MUST NOT be labeled as enforcement-point receipt unless the applicable profile defines the endpoint binding, delivery semantics, persistence point, and failure behavior that make the equivalence valid. | agreement |
| S4.4-1 | 4.4 | 594-595 | MUST | At minimum, a profile that reports enforcement MUST be able to distinguish: | agreement |
| S4.5-1 | 4.5 | 638-640 | MUST | Where independent corroboration is claimed, the observer MUST be independent of both the issuer and the enforcement point under the stated trust model. | agreement |
| S4.5-2 | 4.5 | 640-641 | MUST NOT | An implementation MUST NOT infer independence from a different process name, service label, or signing key alone. | agreement |
| S4.5-3 | 4.5 | 642-643 | MUST NOT | A scoped effect observation for one target or one operation MUST NOT be generalized to every target or every dispatch path. | agreement |
| S5.1-1 | 5.1 | 649-651 | MUST | Each control instruction crossing a control boundary MUST have an identifier that remains stable across issuer, transport, receiver, enforcement, and reconciliation observations. | agreement |
| S5.1-2 | 5.1 | 651-652 | MUST | The identifier's uniqueness scope and reuse rules MUST be defined. | agreement |
| S5.1-3 | 5.1 | 652-655 | MAY, MUST NOT | A decision, task, session, action, or delegation reference MAY also be carried, but it MUST NOT replace the instruction identifier unless the protocol defines identical uniqueness and lifecycle semantics. | agreement |
| S5.1-4 | 5.1 | 657-659 | MUST | If retries create distinct delivery attempts, the profile MUST define an attempt identifier or equivalent rule that prevents observations from different attempts from being silently merged. | agreement |
| S5.2-1 | 5.2 | 663-665 | MUST | Every observation used to correlate a control instruction MUST bind the instruction identifier to a digest of either the exact instruction or a declared canonical projection of it. | agreement |
| S5.2-2 | 5.2 | 665-668 | MUST | The projection, digest algorithm, canonicalization rule, and domain-separation rule, if any, MUST be identified by the applicable protocol or profile. | agreement |
| S5.3-1 | 5.3 | 683-684 | MUST | Each observation MUST identify the observer, the boundary side observed, and the event being asserted. | agreement |
| S5.3-2 | 5.3 | 684-685 | MUST | The evidence profile MUST state how the observer identity and its authority are verified. | agreement |
| S5.3-3 | 5.3 | 685-687 | MUST NOT | If the producer is able to rewrite the purported corroborating record, the record MUST NOT be described as independent evidence. | agreement |
| S5.3-4 | 5.3 | 689-691 | MUST | If a profile permits structural processing when an external trust or authority binding is absent, it MUST expose that limitation through the claim-support qualification defined in Section 6.6. | agreement |
| S5.3-5 | 5.3 | 691-693 | MUST NOT | A self-declared key, role, or observer label MUST NOT silently become fully supported attribution. | agreement |
| S5.4-1 | 5.4 | 697-699 | MUST | When an implementation claims that a control was dispatched, it MUST emit or preserve an issuer-side observation at the last declared issuer-controlled boundary. | ambiguity |
| S5.4-2 | 5.4 | 699-701 | MUST | The observation MUST include the stable identifier, content binding, target, target-set reference, or resolution input, observed time, and boundary description. | agreement |
| S5.4-3 | 5.4 | 703-706 | MUST | Where one instruction resolves to multiple required targets, the profile MUST preserve a stable binding to the Required Target Set, or to a verifiable resolution rule and inputs from which the same set can be reconstructed at the reconciliation cutoff. | agreement |
| S5.4-4 | 5.4 | 708-709 | MUST NOT | If emission fails before that boundary, the implementation MUST NOT report the instruction as dispatched. | agreement |
| S5.4-5 | 5.4 | 709-710 | SHOULD | It SHOULD record the failed emission attempt as a positive failure event. | ambiguity |
| S5.5-1 | 5.5 | 714-716 | MUST NOT | An implementation MUST NOT report delivery to a required target unless it has a matching receiver-side observation or a receipt whose endpoint semantics satisfy Section 4.3. | agreement |
| S5.5-2 | 5.5 | 716-720 | MUST | The observation MUST carry the stable identifier, content binding, receiver identity, required target identity, receiving boundary, observed time, verification result, and an attempt identifier or equivalent retry binding where the profile distinguishes delivery attempts. | agreement |
| S5.5-3 | 5.5 | 733-734 | MAY | A receiver observation MAY satisfy only the Delivery Obligation whose target identity and boundary it is verified to represent. | agreement |
| S5.5-4 | 5.5 | 734-736 | MUST NOT | An observation for target A MUST NOT be used to confirm target B merely because the parent instruction identifier and content digest match. | agreement |
| S5.5-5 | 5.5 | 738-739 | MUST NOT | A receiver MUST NOT acknowledge a digest or instruction identifier it did not read and match. | agreement |
| S5.5-6 | 5.5 | 739-741 | SHOULD | If verification or content matching fails, the receiver SHOULD preserve a scoped failure observation rather than emitting a successful acknowledgement. | agreement |
| S5.6-1 | 5.6 | 745-745 | MUST | Receipt and enforcement MUST be represented as separate facts. | agreement |
| S5.6-2 | 5.6 | 745-748 | MUST | An implementation that reports an enforcement result MUST distinguish at least APPLIED, REFUSED, NO_EFFECT, and UNKNOWN, or define a lossless mapping from its native states to those meanings. | agreement |
| S5.6-3 | 5.6 | 748-749 | MUST NOT | Missing enforcement evidence MUST NOT default to APPLIED. | agreement |
| S5.7-1 | 5.7 | 753-754 | MUST | An observed control effect MUST be represented separately from both delivery and enforcement. | agreement |
| S5.7-2 | 5.7 | 754-756 | MUST | The observation MUST name its predicate, target, method, observer relationship, start and end conditions, and result. | agreement |
| S5.7-3 | 5.7 | 756-758 | MUST, MUST NOT | A claim that no effect occurred MUST be bounded by an observation window and predicate; silence alone MUST NOT be reported as NO_EFFECT. | ambiguity |
| S5.8-1 | 5.8 | 762-763 | MUST | A negative observation MUST record what was positively observed, from which boundary, and as of which cutoff. | ambiguity |
| S5.8-2 | 5.8 | 763-764 | SHOULD | Profiles SHOULD support at least the following conceptual conditions where applicable: | agreement |
| S5.9-1 | 5.9 | 791-792 | MUST | Each timed observation MUST identify its time value and the relevant clock or trust basis. | agreement |
| S5.9-2 | 5.9 | 792-795 | MUST | A profile that reports cross-observer latency or precedence MUST state how clock synchronization, trusted timestamping, causal linkage, or another ordering mechanism supports that claim. | agreement |
| S5.9-3 | 5.9 | 799-800 | MUST | Unsupported ordering claims MUST be omitted or reported as indeterminate. | agreement |
| S5.10-1 | 5.10 | 804-806 | MUST | A reconciler MUST produce a deterministic disposition for every Delivery Obligation and every input record presented under a declared profile. | agreement |
| S5.10-2 | 5.10 | 806-807 | MUST NOT | Malformed, unverifiable, duplicate, conflicting, and unmatched records MUST NOT be silently discarded. | agreement |
| S5.10-3 | 5.10 | 807-809 | MUST NOT | A reconciler MUST NOT produce a successful delivery verdict solely because no failure record exists. | agreement |
| S5.10-4 | 5.10 | 811-813 | MUST | The expected obligation population MUST be constructed from the declared issuer-side inclusion and target-resolution rules rather than solely from the receiver evidence that happens to be present. | agreement |
| S5.10-5 | 5.10 | 818-820 | MAY | A profile MAY add more specific states, provided that it defines a lossless mapping to the minimum set and does not weaken UNCONFIRMED, INVALID, CONFLICT, or INDETERMINATE into success. | agreement |
| S5.10-6 | 5.10 | 822-824 | MUST | If several applicable observations or diagnostics are reduced to one primary per-obligation disposition, the reduction rule MUST be deterministic and reviewable. | agreement |
| S5.10-7 | 5.10 | 824-827 | MUST | All applicable diagnostics, including diagnostics not selected as the primary disposition-driving diagnostic, MUST remain visible in the report or in an explicitly linked diagnostic collection. | agreement |
| S5.11-1 | 5.11 | 847-850 | MUST | An implementation claiming completeness over a set of controls MUST declare a reproducible issuer inclusion rule, Required Target Set or target-resolution rule for each instruction, observation window, reconciliation cutoff, and expected population counts. | agreement |
| S5.11-2 | 5.11 | 850-852 | MUST | Each expected Delivery Obligation MUST appear in exactly one per-obligation disposition. | agreement |
| S5.11-3 | 5.11 | 852-854 | MUST | Each receiver-side input record MUST also be accounted for as matched, orphaned, duplicated, conflicting where the profile uses a separate record class, or invalid. | ambiguity |
| S5.11-4 | 5.11 | 856-859 | MUST | Every instruction in the bounded issuer population MUST remain accounted for during target-set construction, including an instruction whose target resolution succeeds and yields an empty Required Target Set. | agreement |
| S5.11-5 | 5.11 | 859-863 | MUST, MUST, MUST | Where the Required Target Set for an instruction is empty, the instruction MUST remain in the report, the report MUST state that the instruction contributed zero Delivery Obligations, and the report MUST state the rule or condition under which target resolution produced the empty set. | agreement |
| S5.11-6 | 5.11 | 863-865 | MUST NOT | An instruction MUST NOT disappear from reconciliation solely because no Delivery Obligation tuple was added for it. | agreement |
| S5.11-7 | 5.11 | 865-868 | MUST, MUST | The report MUST publish \|I\| alongside \|O\| and MUST publish counts sufficient to distinguish instructions that contributed one or more Delivery Obligations from instructions that contributed zero, as required by Section 6.4. | agreement |
| S5.11-8 | 5.11 | 870-871 | MUST | A profile MUST define whether an empty Required Target Set is a valid terminal resolution. | agreement |
| S5.11-9 | 5.11 | 874-877 | MUST | Where the profile does not permit it, an empty Required Target Set MUST prevent a structural PASS for the affected instruction and for any parent or aggregate scope that depends on it. | agreement |
| S5.11-10 | 5.11 | 877-880 | MUST NOT, MUST NOT | An empty Required Target Set MUST NOT be recorded by inventing a synthetic enforcement target or a synthetic Delivery Obligation, and MUST NOT be classified as EXPLICIT_FAILURE unless a positive, attributable failing condition applies under Section 6.1. | agreement |
| S5.11-11 | 5.11 | 882-884 | MUST NOT | If the implementation cannot define a closed Required Target Set for an instruction, it MUST NOT claim complete delivery for that instruction over an unspecified target population. | agreement |
| S5.11-12 | 5.11 | 884-886 | MAY | It MAY report per-record or per-known-target results with an explicit open-population scope. | agreement |
| S5.11-13 | 5.11 | 902-906 | MAY, MUST NOT | A report MAY state that every member of a declared target set is confirmed when the evidence supports that scoped statement; it MUST NOT promote that statement into "every possible enforcement path was covered" unless the target-set coverage basis separately supports that stronger claim. | agreement |
| S5.12-1 | 5.12 | 910-914 | MUST | If a control instruction refers to an external decision, policy, action, task, target, target set, key, or evidence binding, the applicable protocol or profile MUST define behavior when that reference cannot be resolved, is stale, resolves ambiguously, or resolves to inconsistent content. | ambiguity |
| S5.12-2 | 5.12 | 914-915 | MUST NOT | Unresolved or ambiguous bindings MUST NOT be treated as verified delivery or successful enforcement. | agreement |
| S5.13-1 | 5.13 | 919-920 | MUST | Evidence producers and reconcilers MUST state what each result covers and what it does not cover. | agreement |
| S5.13-2 | 5.13 | 920-924 | MUST NOT | At minimum, integrity, attribution, delivery, enforcement, observed control effect, ordering, population closure, complete mediation, and independent corroboration MUST NOT be implied unless each is separately supported under the declared trust model. | agreement |
| S5.13-3 | 5.13 | 926-928 | MUST, MUST | Where an aggregate result is used to support a relying-party claim, the report MUST identify the claim scope and MUST expose the claim-support qualification defined in Section 6.6. | agreement |
| S5.13-4 | 5.13 | 928-932 | MUST NOT | A structural PASS MUST NOT be rendered or consumed as an unqualified end-to-end success statement when attribution, target-set coverage, ordering, independence, or another claim predicate remains only declared, unverified, or indeterminate. | agreement |
| S5.13-5 | 5.13 | 937-940 | MUST NOT | Evidence that a governance-relevant distinction was preserved at one boundary MUST NOT, by itself, be consumed as evidence that the distinction survived unchanged through later intermediaries to the relying party. | agreement |
| S5.14-1 | 5.14 | 959-960 | MUST NOT | An unacknowledged or unresolved safety-relevant Delivery Obligation MUST NOT be consumed as delivered. | agreement |
| S5.14-2 | 5.14 | 960-963 | SHOULD, SHOULD | A relying system SHOULD expose UNCONFIRMED, CONFLICT, INVALID, and INDETERMINATE results to operational policy and SHOULD define a fail-safe, retry, escalation, or human notification behavior appropriate to the controlled risk. | not_implemented |
| S5.15-1 | 5.15 | 971-973 | MUST | For each Required Target Set used in a bounded reconciliation, the profile MUST state the set identifier or reproducible resolution rule and the basis on which the set is treated as closed. | agreement |
| S5.15-2 | 5.15 | 973-976 | MUST | The report MUST also state whether the completeness of that enumeration for a stronger deployment-level mediation claim is verified under the trust model, merely declared by a source, or indeterminate. | agreement |
| S5.15-3 | 5.15 | 978-979 | MAY, MUST | A profile MAY use different vocabulary, but it MUST preserve the distinction among at least the following conceptual conditions: | agreement |
| S5.15-4 | 5.15 | 996-998 | MUST NOT | It MUST NOT, by itself, support a fully qualified claim of complete mediation across every relevant path. | agreement |
| S5.16-1 | 5.16 | 1015-1020 | MUST | When a profile claims that a source-attributable disposition, outcome, target identity, or other governance-relevant state is preserved across one or more protocol intermediaries, the evidence available to the relying party MUST preserve enough source and transformation information to determine whether the relevant distinction survived the path. | agreement |
| S5.16-2 | 5.16 | 1020-1024 | MUST, MUST | Where a gateway, broker, adapter, or other intermediary transforms the native representation, the applicable profile MUST define a lossless mapping for every governance-relevant state used by the claim or MUST expose that the mapping is incomplete, ambiguous, or unavailable. | agreement |
| S5.16-3 | 5.16 | 1026-1029 | MUST NOT | An intermediary MUST NOT silently collapse distinct applicable states such as deny, defer, reject, timeout, unresolved, or indeterminate into a representation that a relying party can consume as a stronger or different state. | agreement |
| S5.16-4 | 5.16 | 1029-1031 | MUST | If lossless preservation cannot be established, the resulting state MUST remain explicitly qualified or INDETERMINATE according to the profile. | agreement |
| S6.1-1 | 6.1 | 1042-1043 | MUST | A conforming reconciliation profile MUST preserve at least the following meanings: | ambiguity |
| S6.1-2 | 6.1 | 1053-1055 | MUST, MUST NOT | The result MUST state its scope and MUST NOT be generalized to other targets or delivery paths. | agreement |
| S6.2-1 | 6.2 | 1104-1105 | MUST | The report MUST retain the per-target dispositions used to derive that parent result. | ambiguity |
| S6.2-2 | 6.2 | 1107-1109 | MUST NOT | If any required obligation is EXPLICIT_FAILURE, UNCONFIRMED, SUBSTITUTION, CONFLICT, INVALID, or INDETERMINATE, the parent instruction MUST NOT be reported as fully confirmed. | agreement |
| S6.3-1 | 6.3 | 1181-1183 | MAY, MUST | Profile-specific conflict resolution MAY select among duplicate or superseding records, but the discarded alternatives and the selection rule MUST remain reviewable. | agreement |
| S6.4-1 | 6.4 | 1194-1195 | MUST | A reconciliation report that claims complete obligation accounting MUST satisfy: | ambiguity |
| S6.4-2 | 6.4 | 1200-1201 | MAY | T_i MAY be empty when the declared target-resolution rule terminates with no required enforcement target for instruction i. | agreement |
| S6.4-3 | 6.4 | 1203-1205 | MUST, MUST | A report that claims complete accounting MUST therefore also publish \|I\| and MUST satisfy the separate instruction-level conservation equation: | ambiguity |
| S6.4-4 | 6.4 | 1212-1214 | MUST | Each zero-obligation instruction MUST be reported individually with the rule or condition that produced the empty set, as required by Section 5.11. | agreement |
| S6.4-5 | 6.4 | 1219-1220 | MUST | Complete receiver-record accounting MUST separately satisfy: | agreement |
| S6.4-6 | 6.4 | 1224-1226 | MAY | Profiles MAY retain additional record-side classes, including a distinct conflict class, provided that every input record remains accounted for exactly once under a published conservation equation. | agreement |
| S6.4-7 | 6.4 | 1238-1239 | MAY, MUST | Profiles MAY subdivide a class, but the sum of its subdivisions MUST preserve the parent count. | agreement |
| S6.4-8 | 6.4 | 1239-1242 | MUST | Records or targets excluded before population construction MUST be reported with the exclusion rule and count; otherwise the completeness claim is not reproducible. | agreement |
| S6.5-1 | 6.5 | 1246-1247 | MAY | A profile MAY define a structural aggregate result such as PASS, FAIL, or INCONCLUSIVE. | agreement |
| S6.5-2 | 6.5 | 1254-1256 | MUST | * PASS MUST require a closed obligation population, successful population conservation, and every expected Delivery Obligation to meet the profile's successful structural conditions; | agreement |
| S6.5-3 | 6.5 | 1258-1259 | MUST, MUST NOT | * FAIL MUST identify at least one positive failing condition and MUST NOT be inferred solely from missing evidence; | ambiguity |
| S6.5-4 | 6.5 | 1261-1263 | MUST | * UNCONFIRMED, CONFLICT, INVALID, or INDETERMINATE obligation input MUST prevent PASS unless the profile explicitly excluded that obligation before population construction under a published rule; | ambiguity |
| S6.5-5 | 6.5 | 1265-1265 | MUST | * a population-conservation failure MUST prevent PASS; and | agreement |
| S6.5-6 | 6.5 | 1267-1268 | MUST | * the report MUST publish the complete class counts rather than only the aggregate label. | agreement |
| S6.5-7 | 6.5 | 1273-1274 | MUST NOT | Implementations MUST NOT collapse those two dimensions into a bare PASS. | agreement |
| S6.6-1 | 6.6 | 1278-1281 | MUST | For each aggregate claim exposed to a relying party, a report MUST identify the claim scope, including the target set or population, relevant boundaries, observation window or cutoff, and the fact being claimed. | agreement |
| S6.6-2 | 6.6 | 1281-1282 | MUST | The report MUST then preserve a claim-support qualification separate from the structural result. | agreement |
| S6.6-3 | 6.6 | 1293-1296 | MUST | Wherever a structural aggregate result is rendered, returned, exported, or otherwise exposed to a relying party, the corresponding claim scope and claim-support qualification MUST be exposed in the same result context. | ambiguity |
| S6.6-4 | 6.6 | 1297-1298 | MUST NOT | A profile MUST NOT expose a bare structural result that can be consumed as the complete result without that qualification. | agreement |
| S6.6-5 | 6.6 | 1306-1307 | MAY, MUST | A profile MAY use different vocabulary, but it MUST define a lossless mapping to at least the following conceptual meanings: | agreement |
| S6.6-6 | 6.6 | 1317-1318 | MUST | The report MUST name each condition or missing predicate. | agreement |
| S6.6-7 | 6.6 | 1322-1323 | MUST NOT | The claim MUST NOT be rendered as true. | agreement |
| S6.6-8 | 6.6 | 1332-1333 | MUST | Profiles MUST state which missing predicates may produce CONDITIONALLY_SUPPORTED rather than NOT_SUPPORTED. | agreement |
| S6.6-9 | 6.6 | 1333-1335 | MUST NOT | They MUST NOT use conditional support as a silent fallback for a predicate that the profile declares mandatory for the requested claim. | agreement |
| S7-1 | 7 | 1352-1355 | SHOULD | When a governance-relevant transition crosses a protocol or administrative boundary, the protocol or its implementation profile SHOULD provide attachment points for: | not_implemented |
| S7-2 | 7 | 1390-1394 | SHOULD | A protocol or profile that maps native states through an intermediary SHOULD preserve source attribution and lossless distinguishability; if it cannot, the mapping and resulting uncertainty need to remain visible under Section 5.16. | agreement |
| S8.1-1 | 8.1 | 1426-1428 | MUST | A reconciler MUST perform or consume the result of the native verification before treating the artifact as evidence for a control-delivery claim. | agreement |
| S8.1-2 | 8.1 | 1430-1433 | MUST NOT | A self-declared algorithm, key identifier, role, observer label, or target-set coverage claim MUST NOT drive trust without an externally configured or otherwise verified binding when the requested claim requires that trust. | agreement |
| S8.1-3 | 8.1 | 1433-1434 | MUST NOT | Composition MUST NOT strengthen the weakest input beyond its verified meaning. | agreement |
| S8.1-4 | 8.1 | 1434-1436 | MUST | Where structural processing continues despite a missing trust predicate, the claim-support qualification MUST preserve that limitation. | agreement |
| S8.3-1 | 8.3 | 1473-1475 | MUST | Profiles using telemetry MUST state which required bindings are native, derived, declared-only, or absent. | agreement |
| S9.1-1 | 9.1 | 1481-1482 | SHOULD | Deployments SHOULD define acknowledgement and reconciliation deadlines based on the controlled risk and transport characteristics. | not_implemented |
| S9.1-2 | 9.1 | 1484-1486 | SHOULD | A late receiver observation can change UNCONFIRMED to CONFIRMED in a later reconciliation run, but the earlier report and its cutoff SHOULD remain available. | agreement |
| S9.1-3 | 9.1 | 1488-1489 | SHOULD | Retries SHOULD reuse or relate identifiers according to a declared rule. | agreement |
| S9.2-1 | 9.2 | 1496-1498 | SHOULD | A profile SHOULD state whether receiver acknowledgement occurs after parsing, verification, durable persistence, admission to an enforcement queue, or completed enforcement. | agreement |
| S9.2-2 | 9.2 | 1498-1501 | MUST NOT | Implementations MUST NOT use the same acknowledgement value for several of those points unless the profile defines the combined semantics and residual failure window. | agreement |
| S9.3-1 | 9.3 | 1520-1523 | SHOULD | A deployment claiming delivery across multiple required enforcement paths SHOULD bind those paths into a Required Target Set and reconcile each resulting Delivery Obligation separately. | not_implemented |
| S9.3-2 | 9.3 | 1525-1527 | SHOULD | A deployment claiming complete control mediation SHOULD identify the deployment scope and the evidence by which the Required Target Set is considered to cover all relevant paths. | agreement |
| S9.4-1 | 9.4 | 1533-1537 | SHOULD | A profile that reports APPLIED for a freeze, revoke, cancel, or similar control SHOULD define the local effective boundary and the relationship between the control and operations that were already admitted, consumed, dispatched, or in flight when the control took effect. | agreement |
| S9.4-2 | 9.4 | 1539-1542 | MUST NOT, MUST NOT | A reconciler MUST NOT retroactively relabel a boundary transition that occurred before control activation, and MUST NOT relabel an operation as blocked merely because a later control was APPLIED. | ambiguity |
| S9.4-3 | 9.4 | 1547-1550 | MAY | If an operation was admitted before control activation but had not yet crossed a later provider-entry or other enforcement boundary, a subsequently applied control MAY still prevent that later transition under the applicable local semantics. | agreement |
| S9.4-4 | 9.4 | 1551-1552 | MUST, MUST | The report MUST preserve the earlier admission fact and MUST separately preserve the later refusal or blocked transition. | agreement |
| S9.4-5 | 9.4 | 1560-1562 | MUST | Missing authenticated outcome evidence for that operation MUST remain unresolved or indeterminate according to the applicable outcome profile. | agreement |
| S10.4-1 | 10.4 | 1635-1636 | MUST | The evidence layer MUST preserve the uncertain state even when local policy chooses to continue operation. | agreement |
| S11-1 | 11 | 1662-1665 | SHOULD | Implementations SHOULD minimize payloads, use scoped or pseudonymous identifiers where possible, separate identity resolution from routine evidence exchange, apply access controls and retention limits, and support selective disclosure. | not_implemented |
| S11-2 | 11 | 1665-1667 | SHOULD NOT | Raw prompts, chain-of-thought, model context, personal data, and proprietary policy SHOULD NOT be included by default. | not_implemented |
| S11-3 | 11 | 1671-1672 | SHOULD | Profiles SHOULD use commitments, nonces, or access-controlled references where dictionary attacks are relevant. | not_implemented |
| SA.MCC-1 | A.MCC | 2415-2416 | SHOULD | A profile claiming conformance to the reconciliation requirements SHOULD publish machine-readable test vectors for at least: | agreement |
| SA.MCC-2 | A.MCC | 2509-2512 | MUST NOT | 26. a stable instruction identifier survives an intermediary while the governed instruction content changes: identifier continuity alone does not satisfy content binding and MUST NOT produce CONFIRMED; | agreement |
