import os
import base64
from algosdk import mnemonic, transaction
from algosdk.account import address_from_private_key
from algosdk.v2client import algod, indexer


ANCHOR_NOTE_PREFIX = "TP1|"


def _algod_client():
    algod_address = os.getenv("ALGOD_ADDRESS", "http://localhost:4001")
    algod_token = os.getenv("ALGOD_TOKEN", "a" * 64)
    return algod.AlgodClient(algod_token, algod_address)


def _indexer_client():
    indexer_address = os.getenv("INDEXER_ADDRESS", "http://localhost:8980")
    indexer_token = os.getenv("INDEXER_TOKEN", "a" * 64)
    return indexer.IndexerClient(indexer_token, indexer_address)


def _get_private_key_for_sender(sender_wallet):
    private_key = os.getenv("ANCHOR_PRIVATE_KEY", "").strip()
    mnemonic_phrase = os.getenv("ANCHOR_MNEMONIC", "").strip()

    if not private_key and mnemonic_phrase:
        private_key = mnemonic.to_private_key(mnemonic_phrase)

    if not private_key:
        raise RuntimeError("Set ANCHOR_PRIVATE_KEY or ANCHOR_MNEMONIC for non-local networks")

    derived = address_from_private_key(private_key)
    if sender_wallet and derived != sender_wallet:
        raise RuntimeError("ANCHOR_SENDER does not match private key/mnemonic")
    return private_key


def build_anchor_note(voter_ref, payload_hash):
    return f"{ANCHOR_NOTE_PREFIX}{voter_ref}|{payload_hash}"


def parse_anchor_note(note_text):
    if not note_text or not note_text.startswith(ANCHOR_NOTE_PREFIX):
        return None, None
    body = note_text[len(ANCHOR_NOTE_PREFIX):]
    wallet, sep, payload_hash = body.partition("|")
    if not sep or not wallet or not payload_hash:
        return None, None
    return wallet, payload_hash


def anchor_decision_hash(payload_hash, voter_ref):
    sender_wallet = os.getenv("ANCHOR_SENDER")
    if not sender_wallet:
        raise RuntimeError("ANCHOR_SENDER is not set")

    private_key = _get_private_key_for_sender(sender_wallet)
    client = _algod_client()
    params = client.suggested_params()
    note = build_anchor_note(voter_ref, payload_hash).encode("utf-8")
    txn = transaction.PaymentTxn(sender_wallet, params, sender_wallet, 0, note=note)
    signed = txn.sign(private_key)
    txid = client.send_transaction(signed)
    return txid


def fetch_tx_note(tx_id):
    client = _indexer_client()
    tx_info = client.lookup_transaction_by_id(tx_id)
    note_b64 = tx_info.get("transaction", {}).get("note")
    if not note_b64:
        return None
    note_bytes = base64.b64decode(note_b64)
    return note_bytes.decode("utf-8")


def count_wallet_anchors(voter_ref):
    client = _indexer_client()
    sender_wallet = os.getenv("ANCHOR_SENDER")
    if not sender_wallet:
        raise RuntimeError("ANCHOR_SENDER is not set")
    note_prefix = f"{ANCHOR_NOTE_PREFIX}{voter_ref}|".encode("utf-8")

    count = 0
    next_token = None
    while True:
        if next_token:
            res = client.search_transactions(
                address=sender_wallet,
                tx_type="pay",
                note_prefix=note_prefix,
                limit=100,
                next_page=next_token,
            )
        else:
            res = client.search_transactions(
                address=sender_wallet,
                tx_type="pay",
                note_prefix=note_prefix,
                limit=100,
            )
        txns = res.get("transactions", [])
        count += len(txns)
        next_token = res.get("next-token")
        if not next_token:
            break
    return count


def list_anchor_hashes(voter_ref, limit=2000):
    client = _indexer_client()
    sender_wallet = os.getenv("ANCHOR_SENDER")
    if not sender_wallet:
        raise RuntimeError("ANCHOR_SENDER is not set")
    note_prefix = f"{ANCHOR_NOTE_PREFIX}{voter_ref}|".encode("utf-8")

    hashes = []
    next_token = None
    while len(hashes) < limit:
        page_limit = min(100, limit - len(hashes))
        if next_token:
            res = client.search_transactions(
                address=sender_wallet,
                tx_type="pay",
                note_prefix=note_prefix,
                limit=page_limit,
                next_page=next_token,
            )
        else:
            res = client.search_transactions(
                address=sender_wallet,
                tx_type="pay",
                note_prefix=note_prefix,
                limit=page_limit,
            )

        txns = res.get("transactions", [])
        for tx in txns:
            note_b64 = tx.get("note")
            if not note_b64:
                continue
            try:
                note_bytes = base64.b64decode(note_b64)
                note_text = note_bytes.decode("utf-8")
            except Exception:
                continue
            parsed_ref, payload_hash = parse_anchor_note(note_text)
            if parsed_ref == voter_ref and payload_hash:
                hashes.append(payload_hash)

        next_token = res.get("next-token")
        if not next_token:
            break

    return hashes
