//! Die neun normativen Regeln aus Abschnitt 5 des Entwurfs
//! draft-hillier-coverage-attestation-00, geschrieben aus dem Prosatext.
//!
//! NICHT gelesen und NICHT uebersetzt: verify.mjs, verify.py, verify.html des Autors.
//! Feldnamen aus CAP-1.schema.json, das Abschnitt 4 zur normativen Form erklaert.

use crate::json::Wert;

/// Abschnitt 6, geschlossenes Vokabular. Acht Eintraege.
const VOKABULAR: [&str; 8] = [
    "not_applicable",
    "disabled_by_policy",
    "unsupported_input",
    "resource_exhausted",
    "failed",
    "unavailable",
    "out_of_scope",
    "withheld",
];

/// Abschnitt 4.2, drei Basis-Arten.
const BASIS_ARTEN: [&str; 3] = ["catalogue", "enumeration", "declared"];

/// R7 nennt genau diese drei als unvereinbar mit complete=true.
const HART: [&str; 3] = ["failed", "resource_exhausted", "unavailable"];

pub struct Verstoss {
    pub regel: String,
    pub grund: String,
}

pub fn verify(doc: &Wert) -> Vec<Verstoss> {
    let mut f: Vec<Verstoss> = Vec::new();
    let mut fehler = |r: &str, g: String| f.push(Verstoss { regel: r.into(), grund: g });

    // ── R0, shape ────────────────────────────────────────────────────────────
    let obj = match doc.as_objekt() {
        Some(o) => o,
        None => {
            fehler("R0-shape", "das Dokument ist kein Objekt".into());
            return f;
        }
    };
    if obj.get("profile").and_then(|v| v.as_text()) != Some("cap/1") {
        fehler("R0-shape", "profile ist nicht die Zeichenkette cap/1".into());
    }
    let subject_ok = obj
        .get("subject")
        .and_then(|v| v.as_objekt())
        .and_then(|m| m.get("ref"))
        .and_then(|v| v.as_text())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !subject_ok {
        fehler("R0-shape", "kein Subjekt benannt".into());
    }

    let leer: Vec<Wert> = Vec::new();
    let strata_roh = obj.get("strata").and_then(|v| v.as_liste()).unwrap_or(&leer);
    if strata_roh.is_empty() {
        fehler("R0-shape", "kein Stratum vorhanden".into());
    }

    let integrity = obj.get("integrity").and_then(|v| v.as_objekt());
    let complete = integrity.and_then(|m| m.get("complete")).and_then(|v| v.as_wahrheit());
    if integrity.is_none() || complete.is_none() {
        fehler("R0-shape", "integrity fehlt oder complete ist kein Wahrheitswert".into());
    }

    let mut ids: Vec<&str> = Vec::new();
    let mut strata: Vec<&std::collections::BTreeMap<String, Wert>> = Vec::new();
    for s in strata_roh {
        match s.as_objekt() {
            None => fehler("R0-shape", "ein Stratum ist kein Objekt".into()),
            Some(m) => {
                match m.get("id").and_then(|v| v.as_text()) {
                    Some(i) if !i.is_empty() => ids.push(i),
                    _ => fehler("R0-shape", "Stratum ohne id".into()),
                }
                strata.push(m);
            }
        }
    }
    let mut sortiert = ids.clone();
    sortiert.sort_unstable();
    sortiert.dedup();
    if sortiert.len() != ids.len() {
        fehler("R0-shape", "Stratum-Kennungen sind nicht eindeutig".into());
    }

    let sid = |m: &std::collections::BTreeMap<String, Wert>| -> String {
        m.get("id").and_then(|v| v.as_text()).unwrap_or("?").to_string()
    };

    // ── R5, counts well formed ───────────────────────────────────────────────
    // Zuerst, weil R1 auf denselben Zahlen rechnet.
    for m in &strata {
        let id = sid(m);
        let el = m.get("eligible").and_then(|v| v.as_ganzzahl());
        let ex = m.get("examined").and_then(|v| v.as_ganzzahl());
        match el {
            Some(v) if v >= 0 => {}
            _ => fehler("R5-counts-well-formed",
                        format!("{id}: eligible ist keine nicht-negative Ganzzahl")),
        }
        match ex {
            Some(v) if v >= 0 => {}
            _ => fehler("R5-counts-well-formed",
                        format!("{id}: examined ist keine nicht-negative Ganzzahl")),
        }
        if let (Some(e), Some(x)) = (el, ex) {
            if x > e {
                fehler("R5-counts-well-formed",
                       format!("{id}: examined ({x}) uebersteigt eligible ({e})"));
            }
        }
    }

    // ── R1, no silent remainder ──────────────────────────────────────────────
    for m in &strata {
        let id = sid(m);
        let el = m.get("eligible").and_then(|v| v.as_ganzzahl());
        let ex = m.get("examined").and_then(|v| v.as_ganzzahl());
        match m.get("unexamined").and_then(|v| v.as_liste()) {
            None => fehler("R1-no-silent-remainder", format!("{id}: unexamined ist keine Liste")),
            Some(un) => {
                if let (Some(e), Some(x)) = (el, ex) {
                    if e != x + un.len() as i64 {
                        fehler("R1-no-silent-remainder",
                            format!("{id}: eligible {e} ist nicht examined {x} plus {} einzeln aufgefuehrte unexamined",
                                    un.len()));
                    }
                }
            }
        }
    }

    // ── R2, closed disposition ───────────────────────────────────────────────
    for m in &strata {
        let id = sid(m);
        for (i, u) in m.get("unexamined").and_then(|v| v.as_liste()).unwrap_or(&leer).iter().enumerate() {
            match u.as_objekt() {
                None => fehler("R2-closed-disposition", format!("{id}[{i}]: Eintrag ist kein Objekt")),
                Some(um) => {
                    match um.get("unit").and_then(|v| v.as_text()) {
                        Some(s) if !s.is_empty() => {}
                        _ => fehler("R2-closed-disposition", format!("{id}[{i}]: kein unit benannt")),
                    }
                    let d = um.get("disposition").and_then(|v| v.as_text());
                    if !d.map(|x| VOKABULAR.contains(&x)).unwrap_or(false) {
                        fehler("R2-closed-disposition",
                            format!("{id}[{i}]: disposition {:?} steht nicht im geschlossenen Vokabular",
                                    d.unwrap_or("(fehlt)")));
                    }
                }
            }
        }
    }

    // ── R3, withholding is digest-bound ──────────────────────────────────────
    for m in &strata {
        let id = sid(m);
        for (i, u) in m.get("unexamined").and_then(|v| v.as_liste()).unwrap_or(&leer).iter().enumerate() {
            if let Some(um) = u.as_objekt() {
                if um.get("disposition").and_then(|v| v.as_text()) == Some("withheld") {
                    let ok = um.get("withheld_digest").and_then(|v| v.as_text())
                        .map(|s| !s.is_empty()).unwrap_or(false);
                    if !ok {
                        fehler("R3-withholding-digest-bound",
                               format!("{id}[{i}]: withheld ohne withheld_digest"));
                    }
                }
            }
        }
    }

    // ── R4, denominator basis ────────────────────────────────────────────────
    for m in &strata {
        let id = sid(m);
        match m.get("basis").and_then(|v| v.as_objekt()) {
            None => fehler("R4-denominator-basis", format!("{id}: kein basis-Objekt")),
            Some(b) => {
                let kind = b.get("kind").and_then(|v| v.as_text());
                match kind {
                    Some(k) if BASIS_ARTEN.contains(&k) => {
                        if k == "catalogue" {
                            let ok = b.get("catalogue_digest").and_then(|v| v.as_text())
                                .map(|s| !s.is_empty()).unwrap_or(false);
                            if !ok {
                                fehler("R4-denominator-basis",
                                       format!("{id}: catalogue-Basis ohne catalogue_digest"));
                            }
                        }
                        if k == "enumeration" {
                            let ok = b.get("enumeration_method").and_then(|v| v.as_text())
                                .map(|s| !s.is_empty()).unwrap_or(false);
                            if !ok {
                                fehler("R4-denominator-basis",
                                       format!("{id}: enumeration-Basis ohne enumeration_method"));
                            }
                        }
                    }
                    _ => fehler("R4-denominator-basis",
                        format!("{id}: basis.kind {:?} ist nicht aus der Menge", kind.unwrap_or("(fehlt)"))),
                }
            }
        }
    }

    // ── R6, absence is scoped ────────────────────────────────────────────────
    let aa = obj.get("absence_assertions").and_then(|v| v.as_liste()).unwrap_or(&leer);
    if obj.contains_key("absence_assertions")
        && obj.get("absence_assertions").and_then(|v| v.as_liste()).is_none() {
        fehler("R6-absence-is-scoped", "absence_assertions ist keine Liste".into());
    }
    for (i, a) in aa.iter().enumerate() {
        match a.as_objekt() {
            None => fehler("R6-absence-is-scoped", format!("absence[{i}]: Eintrag ist kein Objekt")),
            Some(am) => match am.get("stratum").and_then(|v| v.as_text()) {
                Some(st) if !st.is_empty() => {
                    if !ids.contains(&st) {
                        fehler("R6-absence-is-scoped",
                               format!("absence[{i}]: Stratum {st:?} existiert nicht"));
                    }
                }
                _ => fehler("R6-absence-is-scoped", format!("absence[{i}]: kein Stratum benannt")),
            },
        }
    }

    // ── R7, incomplete is not clean ──────────────────────────────────────────
    let mut hat_harte = false;
    for m in &strata {
        for u in m.get("unexamined").and_then(|v| v.as_liste()).unwrap_or(&leer) {
            if let Some(um) = u.as_objekt() {
                if let Some(d) = um.get("disposition").and_then(|v| v.as_text()) {
                    if HART.contains(&d) { hat_harte = true; }
                }
            }
        }
    }
    if hat_harte && complete == Some(true) {
        fehler("R7-incomplete-not-clean",
            "eine Einheit ist failed/resource_exhausted/unavailable, complete ist trotzdem true".into());
    }
    if complete == Some(false) {
        let ok = integrity.and_then(|m| m.get("capped_to")).and_then(|v| v.as_text())
            .map(|s| !s.is_empty()).unwrap_or(false);
        if !ok {
            fehler("R7-incomplete-not-clean",
                   "complete ist false, aber capped_to nennt kein Verdikt".into());
        }
    }

    // ── R8, supports bounds citation ─────────────────────────────────────────
    let mut zitiert: Vec<&str> = Vec::new();
    for a in aa {
        if let Some(am) = a.as_objekt() {
            if let Some(st) = am.get("stratum").and_then(|v| v.as_text()) { zitiert.push(st); }
        }
    }
    for m in &strata {
        let id = sid(m);
        if zitiert.contains(&id.as_str()) {
            let ok = m.get("supports").and_then(|v| v.as_liste())
                .map(|l| !l.is_empty()).unwrap_or(false);
            if !ok {
                fehler("R8-supports-bounds-citation",
                    format!("{id}: von einer absence assertion zitiert, nennt aber keine supports"));
            }
        }
    }

    f
}
