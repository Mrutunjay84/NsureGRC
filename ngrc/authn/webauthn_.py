"""WebAuthn (D-P0-008 s7.2) on the maintained `webauthn` (py_webauthn) library - no custom parsing.

RP ID and origin allow-list come from settings; attestation = none; challenges are 32 random bytes, stored server-side in
the session, single-use (consumed on first verification attempt, success or failure) and expire after 5 minutes.
Step-up challenges carry a `binding` (e.g. "support.approve:<grant id>") and can only be consumed for that binding.
"""
from __future__ import annotations

import json
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ngrc.core import clock

from .realms import Realm


class WebAuthnError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _store_challenge(realm: Realm, s, challenge: bytes, purpose: str, binding: str = "") -> None:
    exp = clock.now() + timedelta(seconds=settings.WEBAUTHN_CHALLENGE_TTL_S)
    realm.Session.objects.using(realm.db).filter(pk=s.pk).update(
        webauthn_challenge={"challenge": bytes_to_base64url(challenge), "purpose": purpose, "binding": binding,
                            "expires": exp.isoformat()})


def _take_challenge(realm: Realm, s, purpose: str, binding: str = "") -> bytes:
    """Atomically load AND clear the pending challenge: it can be used for exactly one verification attempt."""
    from datetime import datetime

    with transaction.atomic(using=realm.db):
        row = realm.Session.objects.using(realm.db).select_for_update().get(pk=s.pk)
        ch = row.webauthn_challenge
        row.webauthn_challenge = None
        row.save(update_fields=["webauthn_challenge"])
    if not ch or ch.get("purpose") != purpose or ch.get("binding", "") != binding:
        raise WebAuthnError("no_matching_challenge")
    if datetime.fromisoformat(ch["expires"]) <= clock.now():
        raise WebAuthnError("challenge_expired")
    return base64url_to_bytes(ch["challenge"])


def registration_options(realm: Realm, s, account, *, require_uv: bool) -> dict:
    existing = [PublicKeyCredentialDescriptor(id=bytes(c.credential_id))
                for c in realm.WebAuthn.objects.using(realm.db).filter(account=account)]
    opts = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID, rp_name=settings.WEBAUTHN_RP_NAME, user_id=account.id.bytes,
        user_name=account.email, user_display_name=account.display_name or account.email,
        attestation=AttestationConveyancePreference.NONE, challenge=secrets.token_bytes(32),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED if require_uv else UserVerificationRequirement.PREFERRED),
        exclude_credentials=existing,
    )
    _store_challenge(realm, s, opts.challenge, "register")
    return json.loads(options_to_json(opts))


def complete_registration(realm: Realm, s, account, credential: dict, *, require_uv: bool, nickname: str = ""):
    challenge = _take_challenge(realm, s, "register")
    try:
        v = verify_registration_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ALLOWED_ORIGINS, require_user_verification=require_uv)
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        raise WebAuthnError("registration_invalid") from exc
    if realm.WebAuthn.objects.using(realm.db).filter(credential_id=v.credential_id).exists():
        raise WebAuthnError("credential_exists")
    return realm.WebAuthn.objects.using(realm.db).create(
        account=account, credential_id=v.credential_id, public_key=v.credential_public_key, sign_count=v.sign_count,
        aaguid=str(v.aaguid or ""), backup_eligible=str(v.credential_device_type) == "multi_device",
        backup_state=bool(v.credential_backed_up), nickname=nickname[:100])


def authentication_options(realm: Realm, s, account, *, require_uv: bool, purpose: str = "authenticate",
                           binding: str = "") -> dict:
    creds = list(realm.WebAuthn.objects.using(realm.db).filter(account=account, flagged_clone=False))
    if not creds:
        raise WebAuthnError("no_credentials")
    opts = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID, challenge=secrets.token_bytes(32),
        allow_credentials=[PublicKeyCredentialDescriptor(id=bytes(c.credential_id)) for c in creds],
        user_verification=UserVerificationRequirement.REQUIRED if require_uv else UserVerificationRequirement.PREFERRED)
    _store_challenge(realm, s, opts.challenge, purpose, binding)
    return json.loads(options_to_json(opts))


def complete_authentication(realm: Realm, s, account, credential: dict, *, require_uv: bool,
                            purpose: str = "authenticate", binding: str = ""):
    """Returns the credential row on success. Raises WebAuthnError('counter_regression') after flagging a cloned key."""
    challenge = _take_challenge(realm, s, purpose, binding)
    try:
        raw_id = base64url_to_bytes(credential["rawId"] if "rawId" in credential else credential["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError("assertion_invalid") from exc
    cred = realm.WebAuthn.objects.using(realm.db).filter(account=account, credential_id=raw_id).first()
    if cred is None or cred.flagged_clone:
        raise WebAuthnError("unknown_credential")
    try:
        v = verify_authentication_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ALLOWED_ORIGINS, credential_public_key=bytes(cred.public_key),
            credential_current_sign_count=cred.sign_count, require_user_verification=require_uv)
    except InvalidAuthenticationResponse as exc:
        if "sign count" in str(exc).lower():
            realm.WebAuthn.objects.using(realm.db).filter(pk=cred.pk).update(flagged_clone=True)
            raise WebAuthnError("counter_regression") from exc
        raise WebAuthnError("assertion_invalid") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise WebAuthnError("assertion_invalid") from exc
    realm.WebAuthn.objects.using(realm.db).filter(pk=cred.pk).update(sign_count=v.new_sign_count, last_used_at=clock.now())
    return cred
