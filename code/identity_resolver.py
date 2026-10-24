"""
Identity Resolver for Ghost Data Still Exists.
Resolves user identities and their complete graph of current and historical
identifiers (emails, phones, names, hashes, user_id, and audit events).
"""

import csv
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class UserIdentity:
    user_id: str
    name: str
    current_email: str
    current_phone: str
    email_hash: str
    updated_at: str
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_names: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    audit_events: List[Dict[str, str]] = field(default_factory=list)

    def matches_identifier(self, identifier: str) -> bool:
        if not identifier:
            return False
        clean = identifier.strip().lower()
        if clean in {e.lower() for e in self.all_emails}:
            return True
        if clean in {p.lower() for p in self.all_phones}:
            return True
        if clean in {h.lower() for h in self.email_hashes}:
            return True
        if clean == self.user_id.lower():
            return True
        return False


class IdentityResolver:
    def __init__(self, identities_path: str, audit_log_path: str):
        self.identities_path = identities_path
        self.audit_log_path = audit_log_path
        self.users_by_id: Dict[str, UserIdentity] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self._load_identities()
        self._load_audit_logs()

    def _load_identities(self):
        if not os.path.exists(self.identities_path):
            raise FileNotFoundError(f"Identities file not found: {self.identities_path}")

        with open(self.identities_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row["name"].strip() if row.get("name") else ""
                email = row["email"].strip() if row.get("email") else ""
                phone = row["phone"].strip() if row.get("phone") else ""
                email_hash = row["email_hash"].strip() if row.get("email_hash") else ""
                updated_at = row["updated_at"].strip() if row.get("updated_at") else ""

                user = UserIdentity(
                    user_id=uid,
                    name=name,
                    current_email=email,
                    current_phone=phone,
                    email_hash=email_hash,
                    updated_at=updated_at,
                    all_emails={email} if email else set(),
                    all_phones={phone} if phone else set(),
                    all_names={name} if name else set(),
                    email_hashes={email_hash} if email_hash else set(),
                )
                self.users_by_id[uid] = user

                if email:
                    self.email_to_user_id[email.lower()] = uid
                if phone:
                    self.phone_to_user_id[phone] = uid

    def _load_audit_logs(self):
        if not os.path.exists(self.audit_log_path):
            return

        with open(self.audit_log_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                user = self.users_by_id.get(uid)
                if not user:
                    continue

                user.audit_events.append(row)
                field_name = row.get("field_name", "").strip().lower()
                old_val = row.get("old_value", "").strip() if row.get("old_value") else ""
                new_val = row.get("new_value", "").strip() if row.get("new_value") else ""

                if field_name == "email":
                    if old_val:
                        user.all_emails.add(old_val)
                        self.email_to_user_id[old_val.lower()] = uid
                    if new_val:
                        user.all_emails.add(new_val)
                        self.email_to_user_id[new_val.lower()] = uid
                elif field_name == "phone":
                    if old_val:
                        user.all_phones.add(old_val)
                        self.phone_to_user_id[old_val] = uid
                    if new_val:
                        user.all_phones.add(new_val)
                        self.phone_to_user_id[new_val] = uid
                elif field_name == "name":
                    if old_val:
                        user.all_names.add(old_val)
                    if new_val:
                        user.all_names.add(new_val)
                elif field_name == "email_hash":
                    if old_val:
                        user.email_hashes.add(old_val.lower())
                    if new_val:
                        user.email_hashes.add(new_val.lower())

    def resolve_by_email(self, email: str) -> Optional[UserIdentity]:
        if not email:
            return None
        uid = self.email_to_user_id.get(email.strip().lower())
        if uid:
            return self.users_by_id.get(uid)
        return None

    def resolve_by_user_id(self, user_id: str) -> Optional[UserIdentity]:
        if not user_id:
            return None
        return self.users_by_id.get(user_id.strip())

    def resolve_by_phone(self, phone: str) -> Optional[UserIdentity]:
        if not phone:
            return None
        uid = self.phone_to_user_id.get(phone.strip())
        if uid:
            return self.users_by_id.get(uid)
        return None
