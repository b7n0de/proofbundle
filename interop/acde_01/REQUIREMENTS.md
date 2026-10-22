# Requirements of draft-abak-agent-control-delivery-evidence-02

Every sentence of the draft that carries a BCP 14 key word in upper case, outside Section 1.2. Line numbers refer to the plain-text copy with SHA-256 `fe3baeb08c8e0979ca64efece098c972827fab483debe0b2bcbfd697bb714782` (2856 lines). Generated from `requirements.json` and `requirements_map.json`.

| id | section | lines | key words | requirement (quoted) | category |
|---|---|---|---|---|---|
| S2-1 | 2 | 357-360 | MAY | Delivery attempts bind evidence to that base obligation and MAY be reported as lossless subaccounting, but they do not change the cardinality of the base obligation population. | agreement |
| S4-1 | 4 | 529-531 | MAY | An implementation MAY carry the required facts in one artifact, in several artifacts, in protocol fields, in telemetry, or through external references. | not_implemented |
| S4.2-1 | 4.2 | 568-570 | MUST NOT | Receiver evidence, an eventual disposition, or an aggregate result MUST NOT determine whether a candidate instruction or target was included. | agreement |
| S4.2-2 | 4.2 | 570-571 | MUST | Every member of E_i and its exclusion reason MUST be reported separately. | agreement |
| S4.2-3 | 4.2 | 571-572 | MUST | The report MUST distinguish C_i being empty from C_i being non-empty while T_i is empty. | agreement |
| S4.2-4 | 4.2 | 575-577 | MAY | Attempts bind observations and MAY produce subresults under a published deterministic reduction rule. | agreement |
| S4.2-5 | 4.2 | 577-579 | MUST NOT, MUST | They MUST NOT create additional base obligations, and all attempt evidence and diagnostics MUST remain reviewable. | agreement |
| S4.3-1 | 4.3 | 599-602 | MUST NOT | It MUST NOT be labeled as enforcement-point receipt unless the applicable profile defines the endpoint binding, delivery semantics, persistence point, and failure behavior that make the equivalence valid. | agreement |
| S4.4-1 | 4.4 | 607-608 | MUST | At minimum, a profile that reports enforcement MUST be able to distinguish: | agreement |
| S4.5-1 | 4.5 | 653-656 | MAY | A profile MAY use conceptual effect results such as EFFECT_OBSERVED, NO_EFFECT, and UNKNOWN, but these are control-effect values rather than enforcement outcomes. | agreement |
| S4.5-2 | 4.5 | 660-662 | MUST | Where independent corroboration is claimed, the observer MUST be independent of both the issuer and the enforcement point under the stated trust model. | agreement |
| S4.5-3 | 4.5 | 662-663 | MUST NOT | An implementation MUST NOT infer independence from a different process name, service label, or signing key alone. | agreement |
| S4.5-4 | 4.5 | 664-665 | MUST NOT | A scoped effect observation for one target or one operation MUST NOT be generalized to every target or every dispatch path. | agreement |
| S5.1-1 | 5.1 | 679-681 | MUST | Each control instruction crossing a control boundary MUST have an identifier that remains stable across issuer, transport, receiver, enforcement, and reconciliation observations. | agreement |
| S5.1-2 | 5.1 | 681-682 | MUST | The identifier's uniqueness scope and reuse rules MUST be defined. | agreement |
| S5.1-3 | 5.1 | 682-685 | MAY, MUST NOT | A decision, task, session, action, or delegation reference MAY also be carried, but it MUST NOT replace the instruction identifier unless the protocol defines identical uniqueness and lifecycle semantics. | agreement |
| S5.1-4 | 5.1 | 687-689 | MUST | If retries create distinct delivery attempts, the profile MUST define an attempt identifier or equivalent rule that prevents observations from different attempts from being silently merged. | agreement |
| S5.1-5 | 5.1 | 689-691 | MUST | Attempt-level results MUST reduce deterministically to the one instruction-target Delivery Obligation without changing \|O\|. | agreement |
| S5.1-6 | 5.1 | 691-693 | MUST, MUST NOT | The reduction MUST retain every applicable attempt record and diagnostic; a later successful retry MUST NOT erase an earlier failed attempt. | agreement |
| S5.2-1 | 5.2 | 697-699 | MUST | Every observation used to correlate a control instruction MUST bind the instruction identifier to a digest of either the exact instruction or a declared canonical projection of it. | agreement |
| S5.2-2 | 5.2 | 699-702 | MUST | The projection, digest algorithm, canonicalization rule, and domain-separation rule, if any, MUST be identified by the applicable protocol or profile. | agreement |
| S5.3-1 | 5.3 | 710-711 | MUST | Each observation MUST identify the observer, the boundary side observed, and the event being asserted. | agreement |
| S5.3-2 | 5.3 | 711-712 | MUST | The evidence profile MUST state how the observer identity and its authority are verified. | agreement |
| S5.3-3 | 5.3 | 712-714 | MUST NOT | If the producer is able to rewrite the purported corroborating record, the record MUST NOT be described as independent evidence. | agreement |
| S5.3-4 | 5.3 | 716-718 | MUST | If a profile permits structural processing when an external trust or authority binding is absent, it MUST expose that limitation through the claim-support qualification defined in Section 6.6. | agreement |
| S5.3-5 | 5.3 | 718-720 | MUST NOT | A self-declared key, role, or observer label MUST NOT silently become fully supported attribution. | agreement |
| S5.4-1 | 5.4 | 735-737 | MUST | When an implementation claims that a control was dispatched, it MUST emit or preserve an issuer-side observation at the last declared issuer-controlled boundary. | agreement |
| S5.4-2 | 5.4 | 737-739 | MUST | The observation MUST include the stable identifier, content binding, target, target-set reference, or resolution input, observed time, and boundary description. | agreement |
| S5.4-3 | 5.4 | 741-744 | MUST | Where one instruction resolves to multiple required targets, the profile MUST preserve a stable binding to the Required Target Set, or to a verifiable resolution rule and inputs from which the same set can be reconstructed at the reconciliation cutoff. | agreement |
| S5.4-4 | 5.4 | 748-751 | MUST, MUST NOT | The report MUST describe dispatch as NOT_ESTABLISHED or equivalently unsupported; absence alone MUST NOT be rendered as dispatched=false, INVALID, or EXPLICIT_FAILURE. | agreement |
| S5.4-5 | 5.4 | 754-756 | MUST, MUST NOT | The missing-evidence diagnostic MUST remain visible and MUST NOT suppress applicable conflict, structural-invalidity, or scoped-failure evidence. | agreement |
| S5.4-6 | 5.4 | 760-761 | MUST NOT | If emission fails before that boundary, the implementation MUST NOT report the instruction as dispatched. | agreement |
| S5.4-7 | 5.4 | 761-762 | SHOULD | It SHOULD record the failed emission attempt as a positive instruction-level failure event. | not_implemented |
| S5.4-8 | 5.4 | 765-766 | MUST NOT | Otherwise it MUST NOT be fanned out to unrelated targets or consumed as proof of non-delivery. | ambiguity |
| S5.5-1 | 5.5 | 770-772 | MUST NOT | An implementation MUST NOT report delivery to a required target unless it has a matching receiver-side observation or a receipt whose endpoint semantics satisfy Section 4.3. | agreement |
| S5.5-2 | 5.5 | 772-776 | MUST | The observation MUST carry the stable identifier, content binding, receiver identity, required target identity, receiving boundary, observed time, verification result, and an attempt identifier or equivalent retry binding where the profile distinguishes delivery attempts. | agreement |
| S5.5-3 | 5.5 | 789-790 | MAY | A receiver observation MAY satisfy only the Delivery Obligation whose target identity and boundary it is verified to represent. | agreement |
| S5.5-4 | 5.5 | 790-792 | MUST NOT | An observation for target A MUST NOT be used to confirm target B merely because the parent instruction identifier and content digest match. | agreement |
| S5.5-5 | 5.5 | 794-795 | MUST NOT | A receiver MUST NOT acknowledge a digest or instruction identifier it did not read and match. | agreement |
| S5.5-6 | 5.5 | 795-797 | SHOULD | If verification or content matching fails, the receiver SHOULD preserve a scoped failure observation rather than emitting a successful acknowledgement. | agreement |
| S5.6-1 | 5.6 | 801-801 | MUST | Receipt and enforcement MUST be represented as separate facts. | agreement |
| S5.6-2 | 5.6 | 801-804 | MUST | An implementation that reports an enforcement result MUST distinguish at least APPLIED, REFUSED, NO_EFFECT, and UNKNOWN, or define a lossless mapping from its native states to those meanings. | agreement |
| S5.6-3 | 5.6 | 804-805 | MUST NOT | Missing enforcement evidence MUST NOT default to APPLIED. | agreement |
| S5.7-1 | 5.7 | 809-810 | MUST | An observed control effect MUST be represented separately from both delivery and enforcement. | agreement |
| S5.7-2 | 5.7 | 810-812 | MUST | The observation MUST name its predicate, target, method, observer relationship, start and end conditions, and result. | agreement |
| S5.7-3 | 5.7 | 812-814 | MUST, MUST NOT | A claim that no effect occurred MUST be bounded by an observation window and predicate; silence alone MUST NOT be reported as NO_EFFECT. | agreement |
| S5.8-1 | 5.8 | 818-819 | MUST | A negative observation MUST record what was positively observed, from which boundary, and as of which cutoff. | agreement |
| S5.8-2 | 5.8 | 819-820 | SHOULD | Profiles SHOULD support at least the following conceptual conditions where applicable: | agreement |
| S5.8-3 | 5.8 | 836-847 | MAY, MUST NOT | A separately scoped timely-delivery claim MAY have a positive failure result under a frozen profile, but that result MUST NOT be generalized to "never delivered". | not_implemented |
| S5.9-1 | 5.9 | 851-852 | MUST | Each timed observation MUST identify its time value and the relevant clock or trust basis. | agreement |
| S5.9-2 | 5.9 | 852-855 | MUST | A profile that reports cross-observer latency or precedence MUST state how clock synchronization, trusted timestamping, causal linkage, or another ordering mechanism supports that claim. | agreement |
| S5.9-3 | 5.9 | 859-860 | MUST | Unsupported ordering claims MUST be omitted or reported as indeterminate. | agreement |
| S5.10-1 | 5.10 | 864-866 | MUST | A reconciler MUST produce a deterministic disposition for every Delivery Obligation and every input record presented under a declared profile. | agreement |
| S5.10-2 | 5.10 | 866-867 | MUST NOT | Malformed, unverifiable, duplicate, conflicting, and unmatched records MUST NOT be silently discarded. | agreement |
| S5.10-3 | 5.10 | 867-869 | MUST NOT | A reconciler MUST NOT produce a successful delivery verdict solely because no failure record exists. | agreement |
| S5.10-4 | 5.10 | 871-874 | MUST | The expected obligation population MUST be constructed from the declared, versioned issuer-side inclusion, exclusion, and target-resolution rules rather than solely from the receiver evidence that happens to be present. | agreement |
| S5.10-5 | 5.10 | 874-875 | MUST | Those rules and their permitted inputs MUST be frozen before receiver evidence is evaluated. | agreement |
| S5.10-6 | 5.10 | 879-882 | MUST | Applicable records that reuse one stable instruction or obligation identity with different governed content within the identity's declared uniqueness scope MUST produce SUBSTITUTION evidence, including issuer-issuer and issuer-receiver relations. | agreement |
| S5.10-7 | 5.10 | 882-883 | MUST | The conflicting records and provenance MUST remain visible. | agreement |
| S5.10-8 | 5.10 | 883-885 | MUST NOT | Equal identifier strings from distinct valid uniqueness scopes MUST NOT be merged. | ambiguity |
| S5.10-9 | 5.10 | 888-890 | MAY | A profile MAY add more specific states, provided that it defines a lossless mapping to the minimum set and does not weaken UNCONFIRMED, INVALID, CONFLICT, or INDETERMINATE into success. | agreement |
| S5.10-10 | 5.10 | 901-903 | MUST | If several applicable observations or diagnostics are reduced to one primary per-obligation disposition, the reduction rule MUST be deterministic and reviewable. | agreement |
| S5.10-11 | 5.10 | 903-906 | MUST | All applicable diagnostics, including diagnostics not selected as the primary disposition-driving diagnostic, MUST remain visible in the report or in an explicitly linked diagnostic collection. | agreement |
| S5.11-1 | 5.11 | 911-916 | MUST | An implementation claiming completeness over a set of controls MUST declare a reproducible, versioned issuer inclusion and exclusion rule, the permitted issuer-side or target-resolution inputs to those rules, a Required Target Set or target-resolution rule for each instruction, the observation window, the reconciliation cutoff, and expected population counts. | agreement |
| S5.11-2 | 5.11 | 916-917 | MUST | The rules, versions, and permitted inputs MUST be frozen before receiver evidence is evaluated. | agreement |
| S5.11-3 | 5.11 | 917-919 | MUST | Each expected Delivery Obligation MUST appear in exactly one per-obligation disposition. | agreement |
| S5.11-4 | 5.11 | 921-922 | MUST | Every excluded candidate MUST be reported with its reason, rule version, and count separately from the included population. | agreement |
| S5.11-5 | 5.11 | 922-924 | MUST NOT | An exclusion MUST NOT depend on receiver evidence, eventual disposition, or aggregate result. | agreement |
| S5.11-6 | 5.11 | 924-926 | MUST NOT | Changing an exclusion rule, version, or permitted input requires a new versioned reconciliation run and MUST NOT rewrite an earlier run. | not_implemented |
| S5.11-7 | 5.11 | 933-937 | MUST NOT | Empty cardinality alone MUST NOT produce structural PASS: the profile has to predeclare whether a fully accounted all-target exclusion is eligible for a narrowly scoped structural PASS, and the report has to expose the excluded candidates, reasons, rule version, counts, and resulting claim scope. | agreement |
| S5.11-8 | 5.11 | 939-940 | MUST | Each receiver-side input record MUST occupy exactly one mutually exclusive primary record-accounting class under the frozen profile. | agreement |
| S5.11-9 | 5.11 | 942-944 | MAY, MUST NOT | Correlation MAY remain as a relationship or diagnostic on a record whose primary class is duplicate, conflict, substitution, or invalid, but MUST NOT cause a second count. | agreement |
| S5.11-10 | 5.11 | 957-960 | MUST | Every instruction in the bounded issuer population MUST remain accounted for during target-set construction, including an instruction whose target resolution succeeds and yields an empty Required Target Set. | agreement |
| S5.11-11 | 5.11 | 960-964 | MUST, MUST, MUST | Where the Required Target Set for an instruction is empty, the instruction MUST remain in the report, the report MUST state that the instruction contributed zero Delivery Obligations, and the report MUST state the rule or condition under which target resolution produced the empty set. | agreement |
| S5.11-12 | 5.11 | 964-966 | MUST NOT | An instruction MUST NOT disappear from reconciliation solely because no Delivery Obligation tuple was added for it. | agreement |
| S5.11-13 | 5.11 | 966-969 | MUST, MUST | The report MUST publish \|I\| alongside \|O\| and MUST publish counts sufficient to distinguish instructions that contributed one or more Delivery Obligations from instructions that contributed zero, as required by Section 6.4. | agreement |
| S5.11-14 | 5.11 | 971-972 | MUST | A profile MUST define whether an empty Required Target Set is a valid terminal resolution. | agreement |
| S5.11-15 | 5.11 | 975-978 | MUST | Where the profile does not permit it, an empty Required Target Set MUST prevent a structural PASS for the affected instruction and for any parent or aggregate scope that depends on it. | agreement |
| S5.11-16 | 5.11 | 978-981 | MUST NOT, MUST NOT | An empty Required Target Set MUST NOT be recorded by inventing a synthetic enforcement target or a synthetic Delivery Obligation, and MUST NOT be classified as EXPLICIT_FAILURE unless a positive, attributable failing condition applies under Section 6.1. | agreement |
| S5.11-17 | 5.11 | 983-986 | MUST | If the implementation cannot define a closed Required Target Set for an instruction, the instruction MUST be placed in the disjoint target_resolution_unclosed instruction-accounting class with its reason. | agreement |
| S5.11-18 | 5.11 | 989-990 | MAY | Independently closed subscopes MAY be reported only with their narrower scope explicit. | agreement |
| S5.11-19 | 5.11 | 993-997 | MAY, MUST NOT | A report MAY state that every member of a declared target set is confirmed when the evidence supports that scoped statement; it MUST NOT promote that statement into "every possible enforcement path was covered" unless the target-set coverage basis separately supports that stronger claim. | agreement |
| S5.12-1 | 5.12 | 1015-1018 | MUST | If a control instruction refers to an external decision, policy, action, task, target, target set, key, or evidence binding, the applicable protocol or profile MUST classify the verified evidence condition. | ambiguity |
| S5.13-1 | 5.13 | 1032-1033 | MUST | Evidence producers and reconcilers MUST state what each result covers and what it does not cover. | agreement |
| S5.13-2 | 5.13 | 1033-1037 | MUST NOT | At minimum, integrity, attribution, delivery, enforcement, observed control effect, ordering, population closure, complete mediation, and independent corroboration MUST NOT be implied unless each is separately supported under the declared trust model. | agreement |
| S5.13-3 | 5.13 | 1039-1041 | MUST, MUST | Where an aggregate result is used to support a relying-party claim, the report MUST identify the claim scope and MUST expose the claim-support qualification defined in Section 6.6. | agreement |
| S5.13-4 | 5.13 | 1041-1045 | MUST NOT | A structural PASS MUST NOT be rendered or consumed as an unqualified end-to-end success statement when attribution, target-set coverage, ordering, independence, or another claim predicate remains only declared, unverified, or indeterminate. | agreement |
| S5.13-5 | 5.13 | 1050-1053 | MUST NOT | Evidence that a governance-relevant distinction was preserved at one boundary MUST NOT, by itself, be consumed as evidence that the distinction survived unchanged through later intermediaries to the relying party. | agreement |
| S5.14-1 | 5.14 | 1077-1078 | MUST NOT | An unacknowledged or unresolved safety-relevant Delivery Obligation MUST NOT be consumed as delivered. | agreement |
| S5.14-2 | 5.14 | 1078-1081 | SHOULD, SHOULD | A relying system SHOULD expose UNCONFIRMED, CONFLICT, INVALID, and INDETERMINATE results to operational policy and SHOULD define a fail-safe, retry, escalation, or human notification behavior appropriate to the controlled risk. | not_implemented |
| S5.15-1 | 5.15 | 1089-1091 | MUST | For each Required Target Set used in a bounded reconciliation, the profile MUST state the set identifier or reproducible resolution rule and the basis on which the set is treated as closed. | agreement |
| S5.15-2 | 5.15 | 1091-1094 | MUST | The report MUST also state whether the completeness of that enumeration for a stronger deployment-level mediation claim is verified under the trust model, merely declared by a source, or indeterminate. | agreement |
| S5.15-3 | 5.15 | 1096-1097 | MAY, MUST | A profile MAY use different vocabulary, but it MUST preserve the distinction among at least the following conceptual conditions: | agreement |
| S5.15-4 | 5.15 | 1126-1128 | MUST NOT | It MUST NOT, by itself, support a fully qualified claim of complete mediation across every relevant path. | agreement |
| S5.16-1 | 5.16 | 1133-1138 | MUST | When a profile claims that a source-attributable disposition, outcome, target identity, or other governance-relevant state is preserved across one or more protocol intermediaries, the evidence available to the relying party MUST preserve enough source and transformation information to determine whether the relevant distinction survived the path. | agreement |
| S5.16-2 | 5.16 | 1138-1142 | MUST, MUST | Where a gateway, broker, adapter, or other intermediary transforms the native representation, the applicable profile MUST define a lossless mapping for every governance-relevant state used by the claim or MUST expose that the mapping is incomplete, ambiguous, or unavailable. | agreement |
| S5.16-3 | 5.16 | 1144-1147 | MUST NOT | An intermediary MUST NOT silently collapse distinct applicable states such as deny, defer, reject, timeout, unresolved, or indeterminate into a representation that a relying party can consume as a stronger or different state. | agreement |
| S5.16-4 | 5.16 | 1147-1149 | MUST | If lossless preservation cannot be established, the resulting state MUST remain explicitly qualified or INDETERMINATE according to the profile. | agreement |
| S6.1-1 | 6.1 | 1160-1161 | MUST | A conforming reconciliation profile MUST preserve at least the following meanings: | agreement |
| S6.1-2 | 6.1 | 1182-1184 | MUST, MUST NOT | The result MUST state its scope and MUST NOT be generalized to other targets or delivery paths. | agreement |
| S6.2-1 | 6.2 | 1242-1243 | MUST | The report MUST retain the per-target dispositions used to derive that parent result. | agreement |
| S6.2-2 | 6.2 | 1245-1247 | MUST NOT | If any required obligation is EXPLICIT_FAILURE, UNCONFIRMED, SUBSTITUTION, CONFLICT, INVALID, or INDETERMINATE, the parent instruction MUST NOT be reported as fully confirmed. | agreement |
| S6.2-3 | 6.2 | 1252-1254 | MUST NOT | For a valid terminal empty Required Target Set, parent delivery confirmation is NOT_APPLICABLE or absent; it MUST NOT be reported as fully confirmed by vacuous truth. | agreement |
| S6.2-4 | 6.2 | 1254-1257 | MAY | A separately qualified structural PASS MAY cover the valid empty-set resolution only where the frozen profile declared that condition and the report exposes the rule and scope. | agreement |
| S6.3-1 | 6.3 | 1317-1319 | MAY, MUST | Profile-specific conflict resolution MAY select among duplicate or superseding records, but the discarded alternatives and the selection rule MUST remain reviewable. | agreement |
| S6.4-1 | 6.4 | 1351-1352 | MUST | The report MUST distinguish that exclusion-induced result from the terminal-empty case \|C_i\| = 0. | agreement |
| S6.4-2 | 6.4 | 1355-1356 | MUST | A reconciliation report that claims complete obligation accounting MUST satisfy: | agreement |
| S6.4-3 | 6.4 | 1362-1363 | MUST | A report that claims complete instruction accounting MUST publish \|I\| and satisfy: | agreement |
| S6.4-4 | 6.4 | 1369-1371 | MUST | Every member of Ntarget_resolution_unclosed MUST be reported individually with its reason and creates no synthetic target or Delivery Obligation. | agreement |
| S6.4-5 | 6.4 | 1374-1375 | MUST | Every zero-obligation instruction MUST be reported with the frozen rule or condition that produced it. | agreement |
| S6.4-6 | 6.4 | 1375-1377 | MUST | The report MUST distinguish target resolution that terminated with no candidates from a non-empty resolved candidate set whose every member was excluded. | agreement |
| S6.4-7 | 6.4 | 1385-1385 | MUST | Complete receiver-record accounting MUST satisfy: | agreement |
| S6.4-8 | 6.4 | 1393-1394 | MAY | Correlation and other diagnostics MAY be preserved across primary classes but do not add another count. | agreement |
| S6.4-9 | 6.4 | 1394-1396 | MUST NOT | If a profile exposes a parent or derived correlated total, it MUST NOT add that total beside its disjoint subclasses in the conservation equation. | agreement |
| S6.4-10 | 6.4 | 1406-1407 | MAY, MUST | Profiles MAY subdivide a class, but the sum of its subdivisions MUST preserve the parent count. | agreement |
| S6.4-11 | 6.4 | 1407-1409 | MUST | Every excluded candidate, reason, rule version, and count MUST be reported separately. | agreement |
| S6.5-1 | 6.5 | 1414-1415 | MAY | A profile MAY define a structural aggregate result such as PASS, FAIL, or INCONCLUSIVE. | agreement |
| S6.5-2 | 6.5 | 1420-1423 | MUST | If a profile defines these aggregate results, it MUST publish and freeze before evidence evaluation the positive conditions that produce FAIL, including how SUBSTITUTION, CONFLICT, INVALID, and any exclusion-rule violation are handled. | ambiguity |
| S6.5-3 | 6.5 | 1423-1424 | MUST NOT | A profile MUST NOT add, remove, or reinterpret those conditions after observing the evidence. | agreement |
| S6.5-4 | 6.5 | 1428-1430 | MUST | * PASS MUST require a closed obligation population, successful population conservation, and every expected Delivery Obligation to meet the profile's successful structural conditions; | agreement |
| S6.5-5 | 6.5 | 1432-1433 | MUST, MUST NOT | * FAIL MUST identify at least one positive failing condition and MUST NOT be inferred solely from missing evidence; | agreement |
| S6.5-6 | 6.5 | 1435-1438 | MUST | * EXPLICIT_FAILURE, UNCONFIRMED, SUBSTITUTION, CONFLICT, INVALID, or INDETERMINATE obligation input MUST prevent PASS unless the profile explicitly excluded that obligation before population construction under a published rule. | agreement |
| S6.5-7 | 6.5 | 1443-1447 | MUST, MUST NOT | * a missing required issuer observation or dispatch state of NOT_ESTABLISHED MUST prevent structural PASS for the affected scope even when a valid receiver observation is retained; the receiver fact remains independently reportable and MUST NOT be promoted into the missing issuer evidence; | agreement |
| S6.5-8 | 6.5 | 1461-1465 | MUST, MUST NOT | * an exclusion-induced zero-obligation instruction MUST prevent PASS unless the frozen profile expressly permits that case and every resolved candidate, exclusion reason, rule version, and count is established and reflected in the narrow claim scope; it MUST NOT be treated as a terminal empty target resolution; | agreement |
| S6.5-9 | 6.5 | 1467-1470 | MUST | * a population-conservation failure, an outcome-adaptive exclusion, or inability to establish the applied frozen exclusion rule/ version MUST prevent PASS; only a predeclared positive condition can produce FAIL; and | agreement |
| S6.5-10 | 6.5 | 1472-1473 | MUST | * the report MUST publish the complete class counts rather than only the aggregate label. | agreement |
| S6.5-11 | 6.5 | 1478-1479 | MUST NOT | Implementations MUST NOT collapse those two dimensions into a bare PASS. | agreement |
| S6.6-1 | 6.6 | 1483-1486 | MUST | For each aggregate claim exposed to a relying party, a report MUST identify the claim scope, including the target set or population, relevant boundaries, observation window or cutoff, and the fact being claimed. | agreement |
| S6.6-2 | 6.6 | 1486-1487 | MUST | The report MUST then preserve a claim-support qualification separate from the structural result. | agreement |
| S6.6-3 | 6.6 | 1494-1497 | MUST | Wherever a structural aggregate result is rendered, returned, exported, or otherwise exposed to a relying party, the corresponding claim scope and claim-support qualification MUST be exposed in the same result context. | agreement |
| S6.6-4 | 6.6 | 1498-1499 | MUST NOT | A profile MUST NOT expose a bare structural result that can be consumed as the complete result without that qualification. | agreement |
| S6.6-5 | 6.6 | 1507-1508 | MAY, MUST | A profile MAY use different vocabulary, but it MUST define a lossless mapping to at least the following conceptual meanings: | agreement |
| S6.6-6 | 6.6 | 1525-1526 | MUST | The report MUST name each condition or missing predicate. | agreement |
| S6.6-7 | 6.6 | 1530-1531 | MUST NOT | The claim MUST NOT be rendered as true. | agreement |
| S6.6-8 | 6.6 | 1540-1541 | MUST | Profiles MUST state which missing predicates may produce CONDITIONALLY_SUPPORTED rather than NOT_SUPPORTED. | agreement |
| S6.6-9 | 6.6 | 1541-1543 | MUST NOT | They MUST NOT use conditional support as a silent fallback for a predicate that the profile declares mandatory for the requested claim. | agreement |
| S7-1 | 7 | 1548-1551 | SHOULD | When a governance-relevant transition crosses a protocol or administrative boundary, the protocol or its implementation profile SHOULD provide attachment points for: | not_implemented |
| S7-2 | 7 | 1593-1597 | SHOULD | A protocol or profile that maps native states through an intermediary SHOULD preserve source attribution and lossless distinguishability; if it cannot, the mapping and resulting uncertainty need to remain visible under Section 5.16. | agreement |
| S8.1-1 | 8.1 | 1633-1635 | MUST | A reconciler MUST perform or consume the result of the native verification before treating the artifact as evidence for a control-delivery claim. | agreement |
| S8.1-2 | 8.1 | 1637-1640 | MUST NOT | A self-declared algorithm, key identifier, role, observer label, or target-set coverage claim MUST NOT drive trust without an externally configured or otherwise verified binding when the requested claim requires that trust. | agreement |
| S8.1-3 | 8.1 | 1640-1641 | MUST NOT | Composition MUST NOT strengthen the weakest input beyond its verified meaning. | agreement |
| S8.1-4 | 8.1 | 1641-1643 | MUST | Where structural processing continues despite a missing trust predicate, the claim-support qualification MUST preserve that limitation. | agreement |
| S8.3-1 | 8.3 | 1670-1672 | MUST | Profiles using telemetry MUST state which required bindings are native, derived, declared-only, or absent. | agreement |
| S9.1-1 | 9.1 | 1689-1690 | SHOULD | Deployments SHOULD define acknowledgement and reconciliation deadlines based on the controlled risk and transport characteristics. | not_implemented |
| S9.1-2 | 9.1 | 1693-1696 | MUST | A late receiver observation can change UNCONFIRMED to CONFIRMED in a later versioned reconciliation run, but the earlier result, cutoff, and deadline diagnostic MUST remain available. | agreement |
| S9.1-3 | 9.1 | 1696-1698 | MAY | A separate timely-delivery claim MAY fail under a frozen profile without establishing that delivery never occurred. | not_implemented |
| S9.1-4 | 9.1 | 1700-1701 | SHOULD | Retries SHOULD reuse or relate identifiers according to a declared rule. | agreement |
| S9.2-1 | 9.2 | 1708-1710 | SHOULD | A profile SHOULD state whether receiver acknowledgement occurs after parsing, verification, durable persistence, admission to an enforcement queue, or completed enforcement. | agreement |
| S9.2-2 | 9.2 | 1710-1713 | MUST NOT | Implementations MUST NOT use the same acknowledgement value for several of those points unless the profile defines the combined semantics and residual failure window. | agreement |
| S9.3-1 | 9.3 | 1718-1721 | SHOULD | A deployment claiming delivery across multiple required enforcement paths SHOULD bind those paths into a Required Target Set and reconcile each resulting Delivery Obligation separately. | not_implemented |
| S9.3-2 | 9.3 | 1723-1725 | SHOULD | A deployment claiming complete control mediation SHOULD identify the deployment scope and the evidence by which the Required Target Set is considered to cover all relevant paths. | agreement |
| S9.4-1 | 9.4 | 1743-1747 | SHOULD | A profile that reports APPLIED for a freeze, revoke, cancel, or similar control SHOULD define the local effective boundary and the relationship between the control and operations that were already admitted, consumed, dispatched, or in flight when the control took effect. | agreement |
| S9.4-2 | 9.4 | 1749-1752 | MUST NOT, MUST NOT | A reconciler MUST NOT retroactively relabel a boundary transition that occurred before control activation, and MUST NOT relabel an operation as blocked merely because a later control was APPLIED. | agreement |
| S9.4-3 | 9.4 | 1759-1762 | MAY | If an operation was admitted before control activation but had not yet crossed a later provider-entry or other enforcement boundary, a subsequently applied control MAY still prevent that later transition under the applicable local semantics. | agreement |
| S9.4-4 | 9.4 | 1763-1764 | MUST, MUST | The report MUST preserve the earlier admission fact and MUST separately preserve the later refusal or blocked transition. | agreement |
| S9.4-5 | 9.4 | 1772-1774 | MUST | Missing authenticated outcome evidence for that operation MUST remain unresolved or indeterminate according to the applicable outcome profile. | agreement |
| S10.4-1 | 10.4 | 1843-1844 | MUST | The evidence layer MUST preserve the uncertain state even when local policy chooses to continue operation. | agreement |
| S11-1 | 11 | 1877-1880 | SHOULD | Implementations SHOULD minimize payloads, use scoped or pseudonymous identifiers where possible, separate identity resolution from routine evidence exchange, apply access controls and retention limits, and support selective disclosure. | not_implemented |
| S11-2 | 11 | 1880-1882 | SHOULD NOT | Raw prompts, chain-of-thought, model context, personal data, and proprietary policy SHOULD NOT be included by default. | not_implemented |
| S11-3 | 11 | 1886-1887 | SHOULD | Profiles SHOULD use commitments, nonces, or access-controlled references where dictionary attacks are relevant. | not_implemented |
| SA.MCC-1 | A.MCC | 2655-2656 | SHOULD | A profile claiming conformance to the reconciliation requirements SHOULD publish machine-readable test vectors for at least: | agreement |
