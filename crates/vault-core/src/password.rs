//! Cryptographically-secure password generation.
//!
//! Indices are drawn from the OS CSPRNG with rejection sampling, so there is
//! no modulo bias. When length permits, at least one character from each
//! selected class is guaranteed, then the result is shuffled.

use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::error::{Error, Result};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Avoids ambiguous/quoting-hostile characters while staying strong.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

/// Which character classes to include and how long the password should be.
#[derive(Clone, Copy, Debug)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

impl PasswordOptions {
    fn classes(&self) -> Vec<&'static [u8]> {
        let mut v = Vec::with_capacity(4);
        if self.lowercase {
            v.push(LOWER);
        }
        if self.uppercase {
            v.push(UPPER);
        }
        if self.digits {
            v.push(DIGITS);
        }
        if self.symbols {
            v.push(SYMBOLS);
        }
        v
    }
}

/// Generate a password per `opts`. The result is held in a zeroizing buffer so
/// it is wiped when dropped; copy it out only when handing to the caller.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    if opts.length == 0 {
        return Err(Error::InvalidArgument("password length must be > 0"));
    }
    let classes = opts.classes();
    if classes.is_empty() {
        return Err(Error::InvalidArgument(
            "at least one character class required",
        ));
    }

    let alphabet: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();

    let mut chars: Vec<u8> = Vec::with_capacity(opts.length);

    // Guarantee class coverage when there is room for it.
    if opts.length >= classes.len() {
        for class in &classes {
            chars.push(class[random_below(class.len())?]);
        }
    }
    while chars.len() < opts.length {
        chars.push(alphabet[random_below(alphabet.len())?]);
    }

    shuffle(&mut chars)?;

    // `chars` is ASCII by construction, so this is valid UTF-8.
    let password = String::from_utf8(chars).expect("alphabet is ASCII");
    Ok(Zeroizing::new(password))
}

/// Read a site's Password Rules string into options we can generate against.
///
/// The format is Apple's, and it is what both iOS and the web hand us: iOS
/// passes `passwordFieldPasswordRules` with a generate request, and HTML fields
/// carry the same string in a `passwordrules` attribute. Ignoring it produces
/// strong passwords that the site rejects, which teaches people that the
/// generator is broken and to type one themselves.
///
/// ```text
/// minlength: 12; maxlength: 24; required: lower, upper; required: digit;
/// allowed: [-().&@?'#,/&"+];
/// ```
///
/// Anything unrecognised is skipped rather than failing the whole string: this
/// runs on input from arbitrary websites, and a rule we do not understand is a
/// reason to fall back to a strong default, not to refuse to help.
///
/// LIMITATION, deliberate: an explicit `[...]` character set turns symbols OFF
/// rather than generating from that set, because our alphabet may contain
/// characters the site forbids. Twenty alphanumerics is far more entropy than
/// anyone needs and always accepted; a password the form rejects is worth
/// nothing however strong it is.
pub fn options_from_rules(rules: &str, default_length: usize) -> PasswordOptions {
    let mut min_length: Option<usize> = None;
    let mut max_length: Option<usize> = None;
    // None = the site said nothing, which per the format means everything
    // printable is allowed.
    let mut allowed: Option<Classes> = None;
    let mut required = Classes::default();
    let mut explicit_set_seen = false;

    for clause in rules.split(';') {
        let Some((key, value)) = clause.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "minlength" => min_length = value.trim().parse().ok(),
            "maxlength" => max_length = value.trim().parse().ok(),
            "allowed" | "required" => {
                let (classes, explicit) = parse_classes(value);
                explicit_set_seen |= explicit;
                if key == "allowed" {
                    let acc = allowed.get_or_insert_with(Classes::default);
                    acc.merge(classes);
                } else {
                    required.merge(classes);
                }
            }
            _ => {}
        }
    }

    // Required characters are allowed by definition, whatever `allowed` says.
    let mut permitted = allowed.unwrap_or(Classes::all());
    permitted.merge(required);

    // An `allowed:` clause naming only things we do not recognise leaves an
    // empty alphabet, and generation would fail outright — on real input, since
    // websites write this string by hand. Fall back to alphanumeric: accepted
    // everywhere, and still far more entropy at this length than any site needs.
    if permitted == Classes::default() {
        permitted = Classes {
            lower: true,
            upper: true,
            digit: true,
            special: false,
        };
    }

    let mut length = default_length;
    if let Some(min) = min_length {
        length = length.max(min);
    }
    if let Some(max) = max_length {
        // Honoured even when it drops below the default. A form that truncates
        // silently at 16 leaves you with a stored password that does not open
        // the account, and no way to tell why.
        length = length.min(max.max(1));
    }

    PasswordOptions {
        length,
        lowercase: permitted.lower,
        uppercase: permitted.upper,
        digits: permitted.digit,
        // `required: special` still wins: the site insists, so the risk of an
        // unaccepted character is one it has taken on itself.
        symbols: permitted.special && (!explicit_set_seen || required.special),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Classes {
    lower: bool,
    upper: bool,
    digit: bool,
    special: bool,
}

impl Classes {
    fn all() -> Self {
        Self {
            lower: true,
            upper: true,
            digit: true,
            special: true,
        }
    }

    fn merge(&mut self, other: Self) {
        self.lower |= other.lower;
        self.upper |= other.upper;
        self.digit |= other.digit;
        self.special |= other.special;
    }
}

/// Parse one comma-separated class list. Returns the classes it names and
/// whether it contained an explicit `[...]` character set.
fn parse_classes(value: &str) -> (Classes, bool) {
    let mut classes = Classes::default();
    let mut explicit = false;

    // Split on commas OUTSIDE brackets: an explicit set may legitimately
    // contain a comma, as in `[-().&@?'#,/&"+]`, and splitting through it
    // yields two fragments that name nothing and silently drop the set.
    let mut depth = 0usize;
    let mut current = String::new();
    let mut parts = Vec::new();
    for ch in value.chars() {
        match ch {
            '[' => {
                depth += 1;
                current.push(ch);
            }
            ']' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    parts.push(current);

    for part in parts {
        let part = part.trim();
        if part.starts_with('[') {
            explicit = true;
            let inner = part.trim_start_matches('[').trim_end_matches(']');
            for ch in inner.chars() {
                if ch.is_ascii_lowercase() {
                    classes.lower = true;
                } else if ch.is_ascii_uppercase() {
                    classes.upper = true;
                } else if ch.is_ascii_digit() {
                    classes.digit = true;
                } else if !ch.is_whitespace() {
                    classes.special = true;
                }
            }
            continue;
        }
        match part.to_ascii_lowercase().as_str() {
            "lower" => classes.lower = true,
            "upper" => classes.upper = true,
            "digit" | "digits" => classes.digit = true,
            "special" => classes.special = true,
            "ascii-printable" | "unicode" => classes = Classes::all(),
            _ => {}
        }
    }
    (classes, explicit)
}

/// Uniform random index in `0..n` via rejection sampling (no modulo bias).
fn random_below(n: usize) -> Result<usize> {
    debug_assert!(n > 0);
    let range = n as u64;
    let span = 1u64 << 32; // 2^32 outcomes from a u32 draw
    let zone = span - (span % range); // largest multiple of `range` below 2^32
    loop {
        let mut buf = [0u8; 4];
        fill_random(&mut buf)?;
        let x = u32::from_le_bytes(buf) as u64;
        if x < zone {
            return Ok((x % range) as usize);
        }
    }
}

/// In-place Fisher-Yates shuffle using the CSPRNG.
fn shuffle(items: &mut [u8]) -> Result<()> {
    for i in (1..items.len()).rev() {
        let j = random_below(i + 1)?;
        items.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length() {
        let opts = PasswordOptions {
            length: 32,
            ..Default::default()
        };
        assert_eq!(generate_password(&opts).unwrap().len(), 32);
    }

    #[test]
    fn includes_each_selected_class() {
        let opts = PasswordOptions {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        };
        // Run several times since coverage is probabilistic per draw but
        // guaranteed by construction.
        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            assert!(pw.bytes().any(|b| LOWER.contains(&b)));
            assert!(pw.bytes().any(|b| UPPER.contains(&b)));
            assert!(pw.bytes().any(|b| DIGITS.contains(&b)));
            assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn only_uses_selected_classes() {
        let opts = PasswordOptions {
            length: 40,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let pw = generate_password(&opts).unwrap();
        assert!(pw.bytes().all(|b| DIGITS.contains(&b)));
    }

    #[test]
    fn rejects_empty_class_set_and_zero_length() {
        let no_classes = PasswordOptions {
            length: 10,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
        };
        assert!(generate_password(&no_classes).is_err());

        let zero_len = PasswordOptions {
            length: 0,
            ..Default::default()
        };
        assert!(generate_password(&zero_len).is_err());
    }

    #[test]
    fn random_below_stays_in_range() {
        for n in 1..50usize {
            for _ in 0..20 {
                assert!(random_below(n).unwrap() < n);
            }
        }
    }
}

#[cfg(test)]
mod rules_tests {
    use super::*;

    fn opts(rules: &str) -> PasswordOptions {
        options_from_rules(rules, 20)
    }

    /// The generated password must actually satisfy the rules it was given.
    /// Checking the parsed options alone would pass even if generation ignored
    /// them, which is the failure that reaches the user.
    fn generated(rules: &str) -> String {
        generate_password(&opts(rules)).unwrap().to_string()
    }

    #[test]
    fn nothing_said_means_everything_allowed() {
        let o = opts("");
        assert_eq!(o.length, 20);
        assert!(o.lowercase && o.uppercase && o.digits && o.symbols);
    }

    #[test]
    fn lengths_are_honoured_in_both_directions() {
        assert_eq!(opts("minlength: 32;").length, 32);
        // Below our default, and obeyed anyway: a form that truncates at 12
        // stores something that no longer opens the account.
        assert_eq!(opts("maxlength: 12;").length, 12);
        assert_eq!(opts("minlength: 8; maxlength: 16;").length, 16);
        // Contradictory: max wins, so we never exceed what the site accepts.
        assert_eq!(opts("minlength: 40; maxlength: 10;").length, 10);
        assert_eq!(generated("maxlength: 12;").len(), 12);
    }

    #[test]
    fn an_allowed_list_excludes_what_it_omits() {
        let o = opts("allowed: lower, upper, digit;");
        assert!(o.lowercase && o.uppercase && o.digits);
        assert!(!o.symbols, "symbols were not in the allowed list");
        assert!(generated("allowed: lower, upper, digit;")
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));

        let o = opts("allowed: digit;");
        assert!(o.digits && !o.lowercase && !o.uppercase && !o.symbols);
    }

    #[test]
    fn required_classes_are_allowed_even_when_the_allowed_list_forgot_them() {
        let o = opts("allowed: lower; required: digit;");
        assert!(o.lowercase && o.digits);
    }

    #[test]
    fn an_explicit_character_set_turns_symbols_off() {
        // Our symbol alphabet is not a subset of theirs, so using it risks a
        // password the form rejects. Alphanumeric at this length is plenty.
        let o = opts(r#"required: lower, upper, digit; allowed: [-().&@?'#,/&"+];"#);
        assert!(o.lowercase && o.uppercase && o.digits);
        assert!(!o.symbols);
    }

    #[test]
    fn a_comma_inside_an_explicit_set_does_not_split_the_clause() {
        // `[-().&@?'#,/&"+]` contains a comma. Splitting naively leaves the
        // fragment `/&"+]` after it, which parses as nothing — and then a site
        // demanding lower+upper+digit would be told only `lower` is allowed,
        // producing a password it refuses.
        let o = opts(r#"allowed: [,-.], lower, upper, digit;"#);
        assert!(o.lowercase, "the classes after the bracketed set were lost");
        assert!(o.uppercase && o.digits);
    }

    #[test]
    fn ascii_printable_means_all_four_classes() {
        let o = opts("allowed: ascii-printable;");
        assert!(o.lowercase && o.uppercase && o.digits && o.symbols);
    }

    #[test]
    fn required_special_beats_the_conservative_explicit_set_rule() {
        // The site insists on a symbol, so omitting one is a guaranteed
        // rejection while including one is only a possible rejection.
        let o = opts("required: special; allowed: [!@#$];");
        assert!(o.symbols);
    }

    #[test]
    fn junk_falls_back_instead_of_failing() {
        // Arbitrary websites write this string. An unparseable one must leave a
        // usable strong default, not an empty character set.
        for junk in [
            "",
            "   ",
            ";;;",
            "nonsense",
            "minlength: banana;",
            "allowed: fuchsia;",
        ] {
            let o = options_from_rules(junk, 20);
            assert!(o.length > 0, "{junk:?} produced a zero length");
            assert!(
                generate_password(&o).is_ok(),
                "{junk:?} produced options that cannot generate"
            );
        }
    }

    #[test]
    fn real_world_rules_still_generate() {
        // Shapes taken from Apple's published quirks list.
        for rules in [
            "minlength: 8; maxlength: 32; required: lower, upper, digit;",
            "required: upper; required: lower; required: digit; allowed: ascii-printable;",
            "minlength: 20; required: [$%^&*]; allowed: lower, upper, digit;",
        ] {
            let o = options_from_rules(rules, 20);
            let pw = generate_password(&o).unwrap();
            assert!(!pw.is_empty(), "{rules:?}");
            assert_eq!(pw.len(), o.length, "{rules:?}");
        }
    }
}
