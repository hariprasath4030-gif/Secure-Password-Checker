"""
Password strength checker.

Provides check_password_strength(password: str, min_length: int = 8) -> dict
and a CLI that hides input using getpass.getpass().

Do not log or store the password.
"""
from __future__ import annotations

import re
import json
import argparse
import sys
from getpass import getpass
from typing import Dict, Any

SPECIAL_CHARS = r"!@#$%^&*(),.?\":{}|<>"


def check_password_strength(password: str, min_length: int = 8) -> Dict[str, Any]:
    """Check the password and return a structured result.

    Returns a dict with keys: score (int 0-5), strength (Weak|Medium|Strong),
    failing_rules (list of rule names), suggestions (list of strings).
    """
    if password is None:
        password = ""

    checks = {}
    checks["length"] = len(password) >= min_length
    checks["digit"] = bool(re.search(r"\d", password))
    checks["lowercase"] = bool(re.search(r"[a-z]", password))
    checks["uppercase"] = bool(re.search(r"[A-Z]", password))
    checks["special"] = bool(re.search(fr"[{SPECIAL_CHARS}]", password))

    score = sum(bool(v) for v in checks.values())

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    failing = [name for name, ok in checks.items() if not ok]
    suggestions = []
    if "length" in failing:
        suggestions.append(f"Make it at least {min_length} characters long")
    if "digit" in failing:
        suggestions.append("Add a digit (0-9)")
    if "lowercase" in failing:
        suggestions.append("Add a lowercase letter (a-z)")
    if "uppercase" in failing:
        suggestions.append("Add an uppercase letter (A-Z)")
    if "special" in failing:
        suggestions.append(f"Add a special character like {SPECIAL_CHARS}")

    # Extra suggestion for longer passwords
    if len(password) < 12:
        suggestions.append("Consider making it 12+ characters for extra security")

    return {
        "score": score,
        "strength": strength,
        "failing_rules": failing,
        "suggestions": suggestions,
    }


def _parse_args():
    parser = argparse.ArgumentParser(description="Password strength checker")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    parser.add_argument("--suggest", action="store_true", help="Show improvement suggestions")
    parser.add_argument("--stdin", action="store_true", help="Read password from stdin (useful for piping)")
    parser.add_argument("--min-length", type=int, default=8, help="Minimum length to require (default: 8)")
    return parser.parse_args()


def main():
    args = _parse_args()
    if args.stdin:
        password = sys.stdin.read().rstrip("\n")
    else:
        # Hide input by default
        password = getpass("Enter your password: ")

    result = check_password_strength(password, min_length=args.min_length)

    if args.json:
        out = {"score": result["score"], "strength": result["strength"]}
        if args.suggest:
            out["failing_rules"] = result["failing_rules"]
            out["suggestions"] = result["suggestions"]
        print(json.dumps(out))
    else:
        print(f"Password Strength: {result['strength']}")
        if args.suggest:
            print("Suggestions:")
            for s in result["suggestions"]:
                print(f" - {s}")


if __name__ == "__main__":
    main()
