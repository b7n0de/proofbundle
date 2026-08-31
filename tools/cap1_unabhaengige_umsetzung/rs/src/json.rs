//! Minimaler, strenger JSON-Leser. Von Hand geschrieben, ohne Fremdcode.
//!
//! WARUM VON HAND: die Python-Seite dieser Doppelumsetzung benutzt Pythons `json`.
//! Teilte sich Rust denselben Parser, waere der Vergleich zweier Umsetzungen um genau
//! die Schicht aermer, in der sich Lesarten am ehesten unterscheiden — die Zahlen.
//!
//! BEWUSSTE ENTSCHEIDUNG: `Zahl` unterscheidet Ganzzahl-SYNTAX von Gleitkomma-SYNTAX.
//! JSON selbst kennt diese Unterscheidung nicht (RFC 8259 hat einen Zahltyp). Der
//! Entwurf verlangt in R5 aber "non-negative integers". Ob `5.0` eine Ganzzahl ist,
//! ist damit eine Auslegungsfrage, und diese Umsetzung haelt beide Formen auseinander,
//! damit die Frage MESSBAR wird statt still entschieden.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Wert {
    Null,
    Wahrheit(bool),
    GanzZahl(i64),
    KommaZahl(f64),
    Text(String),
    Liste(Vec<Wert>),
    Objekt(BTreeMap<String, Wert>),
}

impl Wert {
    pub fn as_objekt(&self) -> Option<&BTreeMap<String, Wert>> {
        if let Wert::Objekt(m) = self { Some(m) } else { None }
    }
    pub fn as_liste(&self) -> Option<&Vec<Wert>> {
        if let Wert::Liste(v) = self { Some(v) } else { None }
    }
    pub fn as_text(&self) -> Option<&str> {
        if let Wert::Text(s) = self { Some(s) } else { None }
    }
    pub fn as_wahrheit(&self) -> Option<bool> {
        if let Wert::Wahrheit(b) = self { Some(*b) } else { None }
    }
    /// Ganzzahl NUR bei Ganzzahl-Syntax. `5.0` ergibt hier bewusst None.
    pub fn as_ganzzahl(&self) -> Option<i64> {
        if let Wert::GanzZahl(i) = self { Some(*i) } else { None }
    }
}

pub struct Leser<'a> {
    b: &'a [u8],
    i: usize,
}

pub fn lies(s: &str) -> Result<Wert, String> {
    let mut l = Leser { b: s.as_bytes(), i: 0 };
    l.leerraum();
    let w = l.wert()?;
    l.leerraum();
    if l.i != l.b.len() {
        return Err(format!("Rest nach dem Dokument an Position {}", l.i));
    }
    Ok(w)
}

impl<'a> Leser<'a> {
    fn leerraum(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn erwarte(&mut self, c: u8) -> Result<(), String> {
        if self.i < self.b.len() && self.b[self.i] == c {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("erwartet {:?} an Position {}", c as char, self.i))
        }
    }
    fn wert(&mut self) -> Result<Wert, String> {
        if self.i >= self.b.len() {
            return Err("Dokument endet vorzeitig".into());
        }
        match self.b[self.i] {
            b'{' => self.objekt(),
            b'[' => self.liste(),
            b'"' => Ok(Wert::Text(self.text()?)),
            b't' => { self.woertlich("true")?; Ok(Wert::Wahrheit(true)) }
            b'f' => { self.woertlich("false")?; Ok(Wert::Wahrheit(false)) }
            b'n' => { self.woertlich("null")?; Ok(Wert::Null) }
            _ => self.zahl(),
        }
    }
    fn woertlich(&mut self, s: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(())
        } else {
            Err(format!("erwartet {} an Position {}", s, self.i))
        }
    }
    fn objekt(&mut self) -> Result<Wert, String> {
        self.erwarte(b'{')?;
        let mut m = BTreeMap::new();
        self.leerraum();
        if self.i < self.b.len() && self.b[self.i] == b'}' {
            self.i += 1;
            return Ok(Wert::Objekt(m));
        }
        loop {
            self.leerraum();
            let k = self.text()?;
            self.leerraum();
            self.erwarte(b':')?;
            self.leerraum();
            let v = self.wert()?;
            // Doppelter Schluessel: RFC 8259 laesst das Verhalten offen. Diese Umsetzung
            // verweigert, statt still einen der beiden zu waehlen.
            if m.insert(k.clone(), v).is_some() {
                return Err(format!("doppelter Schluessel {:?}", k));
            }
            self.leerraum();
            if self.i < self.b.len() && self.b[self.i] == b',' {
                self.i += 1;
                continue;
            }
            self.erwarte(b'}')?;
            return Ok(Wert::Objekt(m));
        }
    }
    fn liste(&mut self) -> Result<Wert, String> {
        self.erwarte(b'[')?;
        let mut v = Vec::new();
        self.leerraum();
        if self.i < self.b.len() && self.b[self.i] == b']' {
            self.i += 1;
            return Ok(Wert::Liste(v));
        }
        loop {
            self.leerraum();
            v.push(self.wert()?);
            self.leerraum();
            if self.i < self.b.len() && self.b[self.i] == b',' {
                self.i += 1;
                continue;
            }
            self.erwarte(b']')?;
            return Ok(Wert::Liste(v));
        }
    }
    fn text(&mut self) -> Result<String, String> {
        self.erwarte(b'"')?;
        let mut s = String::new();
        loop {
            if self.i >= self.b.len() {
                return Err("Zeichenkette endet nicht".into());
            }
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    if self.i >= self.b.len() {
                        return Err("Fluchtzeichen endet vorzeitig".into());
                    }
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\u{8}'),
                        b'f' => s.push('\u{c}'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            let h = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| "ungueltige \\u-Folge".to_string())?;
                            let n = u32::from_str_radix(h, 16)
                                .map_err(|_| "ungueltige \\u-Folge".to_string())?;
                            self.i += 4;
                            s.push(char::from_u32(n).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(format!("unbekanntes Fluchtzeichen {:?}", e as char)),
                    }
                }
                _ => {
                    // Mehrbytefolgen unveraendert uebernehmen.
                    let start = self.i - 1;
                    let mut end = self.i;
                    while end < self.b.len() && (self.b[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    s.push_str(
                        std::str::from_utf8(&self.b[start..end])
                            .map_err(|_| "ungueltiges UTF-8".to_string())?,
                    );
                    self.i = end;
                }
            }
        }
    }
    fn zahl(&mut self) -> Result<Wert, String> {
        // RFC 8259 Abschnitt 6, die Zahlengrammatik BUCHSTABENGETREU:
        //   number = [ minus ] int [ frac ] [ exp ]
        //   int    = zero / ( digit1-9 *DIGIT )
        // "Leading zeros are not allowed." Die erste Fassung dieses Parsers las Ziffern
        // GIERIG und nahm damit 04 an — ein Defekt DIESER Umsetzung, gefunden von der
        // eigenen Sonde S8, nicht vom Entwurf. Er stand kurz davor, als Abweichung des
        // fremden Dokuments gemeldet zu werden.
        let start = self.i;
        if self.i < self.b.len() && self.b[self.i] == b'-' {
            self.i += 1;
        }
        // int
        if self.i >= self.b.len() || !self.b[self.i].is_ascii_digit() {
            return Err(format!("keine Ziffer an Position {}", self.i));
        }
        if self.b[self.i] == b'0' {
            self.i += 1;
            if self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
                return Err(format!("fuehrende Null an Position {}", start));
            }
        } else {
            while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
                self.i += 1;
            }
        }
        let mut komma = false;
        // frac
        if self.i < self.b.len() && self.b[self.i] == b'.' {
            komma = true;
            self.i += 1;
            if self.i >= self.b.len() || !self.b[self.i].is_ascii_digit() {
                return Err(format!("Nachkommastelle fehlt an Position {}", self.i));
            }
            while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
                self.i += 1;
            }
        }
        // exp
        if self.i < self.b.len() && (self.b[self.i] | 0x20) == b'e' {
            komma = true;
            self.i += 1;
            if self.i < self.b.len() && matches!(self.b[self.i], b'+' | b'-') {
                self.i += 1;
            }
            if self.i >= self.b.len() || !self.b[self.i].is_ascii_digit() {
                return Err(format!("Exponent ohne Ziffer an Position {}", self.i));
            }
            while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
                self.i += 1;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| "ungueltige Zahl".to_string())?;
        if komma {
            s.parse::<f64>().map(Wert::KommaZahl).map_err(|e| e.to_string())
        } else {
            s.parse::<i64>().map(Wert::GanzZahl).map_err(|e| e.to_string())
        }
    }
}
