"""Canary (decoy) files. Ransomware enumerates and encrypts everything; no legitimate program should ever
modify, rename or delete these. A verified change is near-zero-false-positive evidence that does not depend on
rates, entropy or process attribution. Content hash is stored so metadata-only touches (atime/mtime) don't trip it."""
import hashlib
import os
import random
import time
import uuid

# Sort first and last in directory listings, look valuable to an attacker.
# Ordered so any prefix is spread across the alphabet (attackers walk files in name or directory order).
CANARY_NAMES = ("!!_important_passwords_backup.txt", "zz_family_documents_notes.txt", "mm_client_contracts_index.txt",
                "!!_accounts_2026.csv", "aa_wallet_recovery_notes.txt", "tt_photos_inventory.csv",
                "0_bank_statements_summary.csv", "ff_tax_returns_2025.txt")


# Per-install randomisation: one slot per prefix (so decoys stay spread across the alphabet), stem and year chosen from a
# seed stored in the config table. An attacker cannot ship a fixed skip-list of decoy names.
_PREFIXES = ("!!_", "aa_", "mm_", "tt_", "zz_", "0_", "ff_", "!!_")
_STEMS = ("important_passwords_backup", "family_documents_notes", "client_contracts_index", "accounts", "wallet_recovery_notes",
          "photos_inventory", "bank_statements_summary", "tax_returns", "insurance_policies", "salary_records",
          "project_credentials", "invoices_archive", "medical_receipts", "property_papers", "exam_results_backup", "vpn_keys_notes")


def names_for(seed):
    """Deterministic list of 8 decoy file names for a seed; an empty seed gives the fixed legacy list."""
    if not seed:
        return CANARY_NAMES
    rnd = random.Random(seed)
    stems = rnd.sample(_STEMS, len(_PREFIXES))
    out = []
    for pre, stem in zip(_PREFIXES, stems):
        ext = rnd.choice((".txt", ".csv"))
        year = rnd.choice(("", "_2025", "_2026", "_old", "_final"))
        out.append(f"{pre}{stem}{year}{ext}")
    return tuple(out)


def make_content(name):
    token = uuid.uuid4().hex
    body = (f"Personal backup notes - do not delete. ref {token}\n" +
            "".join(f"entry {i}: account-{token[i:i + 6]} / archived {time.strftime('%Y-%m-%d')}\n" for i in range(40)))
    return body.encode()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def plant(path, name):
    data = make_content(name)
    p = os.path.join(path, name)
    with open(p, "wb") as f:
        f.write(data)
    return p, sha256_bytes(data)
