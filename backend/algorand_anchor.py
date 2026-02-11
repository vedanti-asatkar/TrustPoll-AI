import os
import base64
from algosdk import transaction
from algosdk.v2client import algod, indexer
from algosdk.kmd import KMDClient


def _algod_client():
    algod_address = os.getenv("ALGOD_ADDRESS", "http://localhost:4001")
    algod_token = os.getenv("ALGOD_TOKEN", "a" * 64)
    return algod.AlgodClient(algod_token, algod_address)


def _kmd_client():
    kmd_address = os.getenv("KMD_ADDRESS", "http://localhost:4002")
    kmd_token = os.getenv("KMD_TOKEN", "a" * 64)
    return KMDClient(kmd_token, kmd_address)


def _indexer_client():
    indexer_address = os.getenv("INDEXER_ADDRESS", "http://localhost:8980")
    indexer_token = os.getenv("INDEXER_TOKEN", "a" * 64)
    return indexer.IndexerClient(indexer_token, indexer_address)


def _get_private_key_from_kmd(sender_wallet, wallet_name, wallet_password):
    kmd = _kmd_client()
    wallets = kmd.list_wallets()
    target = next((w for w in wallets if w["name"] == wallet_name), None)
    if not target:
        raise RuntimeError("KMD wallet not found")
    handle = kmd.init_wallet_handle(target["id"], wallet_password)
    try:
        keys = kmd.list_keys(handle)
        if sender_wallet not in keys:
            raise RuntimeError("Sender wallet not found in KMD wallet")
        private_key = kmd.export_key(handle, wallet_password, sender_wallet)
        return private_key
    finally:
        kmd.release_wallet_handle(handle)


def anchor_decision_hash(payload_hash, sender_wallet=None):
    sender_wallet = sender_wallet or os.getenv("ANCHOR_SENDER")
    if not sender_wallet:
        raise RuntimeError("ANCHOR_SENDER is not set")

    wallet_name = os.getenv("KMD_WALLET_NAME", "unencrypted-default-wallet")
    wallet_password = os.getenv("KMD_WALLET_PASSWORD", "")

    private_key = _get_private_key_from_kmd(sender_wallet, wallet_name, wallet_password)
    client = _algod_client()
    params = client.suggested_params()
    note = payload_hash.encode("utf-8")
    txn = transaction.PaymentTxn(sender_wallet, params, sender_wallet, 0, note=note)
    signed = txn.sign(private_key)
    txid = client.send_transaction(signed)
    return txid


def fetch_tx_note(tx_id):
    client = _algod_client()
    tx_info = client.pending_transaction_info(tx_id)
    note_b64 = tx_info.get("txn", {}).get("note")
    if not note_b64:
        return None
    note_bytes = base64.b64decode(note_b64)
    return note_bytes.decode("utf-8")


def count_wallet_anchors(wallet):
    client = _indexer_client()
    count = 0
    next_token = None
    while True:
        if next_token:
            res = client.search_transactions(address=wallet, tx_type="pay", limit=100, next_page=next_token)
        else:
            res = client.search_transactions(address=wallet, tx_type="pay", limit=100)
        txns = res.get("transactions", [])
        for tx in txns:
            if tx.get("note"):
                count += 1
        next_token = res.get("next-token")
        if not next_token:
            break
    return count
