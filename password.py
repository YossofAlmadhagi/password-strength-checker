import string
import math

def password_strength(password: str, attempts_per_second: float = 1_000_000_000):
    """Evaluate password strength robustly and return a result dict.

    Returns keys: password, length, charset_size, entropy_bits, combinations (int or None),
    combinations_log10 (if combinations is None), time_seconds (float or inf),
    time_log10 (if time_seconds is inf), time_human, score, strength.
    """
    length = len(password)
    charset = 0

    # charset detection
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)

    # Use entropy and log10 to avoid huge integers when necessary
    if charset <= 0 or length == 0:
        entropy_bits = 0.0
        combinations = 0
        combinations_log10 = 0.0
    else:
        entropy_bits = length * math.log2(charset)
        combinations_log10 = entropy_bits * math.log10(2)
        if entropy_bits < 63:
            combinations = int(charset ** length)
        else:
            combinations = None

    # Time to brute-force (seconds), but avoid overflow by using log10
    if entropy_bits <= 0:
        time_seconds = 0.0
        time_log10 = float("-inf")
    else:
        time_log10 = combinations_log10 - math.log10(attempts_per_second)
        if time_log10 < 308:
            time_seconds = 10 ** time_log10
        else:
            time_seconds = float("inf")

    def _human_time(seconds_log10: float = None, seconds: float = None) -> str:
        """Format seconds to a short human-readable string or scientific years for very large values."""
        seconds_per_year = 60 * 60 * 24 * 365
        if seconds is not None and math.isfinite(seconds) and seconds < 1e9 * seconds_per_year:
            s = seconds
            intervals = (
                (seconds_per_year, "year"),
                (60 * 60 * 24, "day"),
                (60 * 60, "hour"),
                (60, "minute"),
                (1, "second"),
            )
            parts = []
            for unit_secs, name in intervals:
                if s >= unit_secs:
                    qty = int(s // unit_secs)
                    s -= qty * unit_secs
                    parts.append(f"{qty} {name}{'s' if qty != 1 else ''}")
                if len(parts) >= 2:
                    break
            return ", ".join(parts) if parts else "<1 second"

        if seconds_log10 is None or not math.isfinite(seconds_log10):
            return "instant"
        log10_years = seconds_log10 - math.log10(seconds_per_year)
        if log10_years < 6:
            years = 10 ** log10_years
            return f"{years:.2f} years"
        return f"~1e{int(math.floor(log10_years))} years"

    time_human = _human_time(seconds_log10=time_log10, seconds=time_seconds)

    # scoring
    if entropy_bits < 28:
        score = 10
        strength = "Very Weak"
    elif entropy_bits < 36:
        score = 30
        strength = "Weak"
    elif entropy_bits < 60:
        score = 60
        strength = "Moderate"
    elif entropy_bits < 90:
        score = 85
        strength = "Strong"
    else:
        score = 100
        strength = "Very Strong"

    return {
        "password": password,
        "length": length,
        "charset_size": charset,
        "entropy_bits": round(entropy_bits, 2),
        "combinations": combinations,
        "combinations_log10": round(combinations_log10, 2) if combinations is None else None,
        "time_seconds": time_seconds,
        "time_log10": round(time_log10, 2) if time_seconds == float('inf') else None,
        "time_human": time_human,
        "score": score,
        "strength": strength,
    }
if __name__== "__main__":
    try:
        pw = input("Enter password to evaluate: ")
    except KeyboardInterrupt:
        print("\nCancelled.")
        raise SystemExit(0)    

    res = password_strength(pw)
    print(f"\nLength: {res['length']}")
    print(f"Charset_size: {res['charset_size']}")
    print(f"Entropy_(bits): {res['entropy_bits']}")
    print(f"Combinations: {res['combinations']}")
    print(f"Estimeted_time_to_crack: {res['time_human']}")
    print(f"Score: {res['score']} ({res['strength']})\n")
       