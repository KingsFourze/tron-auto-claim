import asyncio
from typing import Optional, Literal
import hashlib, base58
from Crypto.Hash import keccak
from coincurve import PrivateKey as CoincurvePrivateKey
from httpx import AsyncClient
from datetime import datetime

from . import logger

def calc_address_from_priv_key(private_key: bytes) -> str:
    sk = CoincurvePrivateKey(private_key)
    pk = sk.public_key.format(compressed=False)[1:] # remove the 0x04 prefix for uncompressed keys

    h = keccak.new(digest_bits=256).update(pk).digest()
    address_bytes = b'\x41' + h[-20:] # Tron addresses start with 0x41
    tron_address = base58.b58encode_check(address_bytes).decode("utf-8")
    return tron_address

def sign_transaction(transaction: dict, priv_key: bytes) -> dict:
    sk = CoincurvePrivateKey(priv_key)

    raw_data = bytes.fromhex(transaction["raw_data_hex"])
    raw_data_hash = hashlib.sha256(raw_data).digest()

    raw_signature = sk.sign_recoverable(raw_data_hash, hasher=None)
    normalized_signature = raw_signature.hex()[:64] + raw_signature.hex()[64:].rjust(64, '0')
    
    transaction["signature"] = [normalized_signature]
    return transaction

class DelegateInfo:
    def __init__(self, to_address: str, bandwidth: int, energy: int, bandwidth_expiry: Optional[datetime] = None, energy_expiry: Optional[datetime] = None):
        self.to_address = to_address
        self.bandwidth_sun = bandwidth
        self.energy_sun = energy
        self.bandwidth_expiry = bandwidth_expiry
        self.energy_expiry = energy_expiry

async def get_delegate_info(client: AsyncClient, address: str) -> list[DelegateInfo]:
    # Get delegated accounts for the address
    try:
        url = "https://api.trongrid.io/wallet/getdelegatedresourceaccountindexv2"
        payload = {
            "value": address,
            "visible": True
        }

        response = await client.post(url, json=payload)
        response.raise_for_status()
    except Exception as e:
        logger.log(f"Error fetching delegate info for address {address}: {e}", logger.LogLevel.ERROR)
        return None
    
    await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits
    
    # Process response to get delegated accounts
    resp = response.json()
    if "toAccounts" not in resp:
        logger.log(f"No delegate accounts found for {address}", logger.LogLevel.INFO)
        return []
    delegate_accounts : list[str] = resp["toAccounts"]

    # For each delegated account, fetch the delegated resource info
    delegate_infos : list[DelegateInfo] = []
    url = "https://api.trongrid.io/wallet/getdelegatedresourcev2"
    payload = {
        "fromAddress": address,
        "visible": True
    }
    for acc in delegate_accounts:
        payload["toAddress"] = acc
        try:
            response = await client.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logger.log(f"Error fetching delegate resource for {acc}: {e}", logger.LogLevel.ERROR)
            continue
        
        await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

        resp = response.json()
        delegated_resource = resp.get("delegatedResource", [])

        for r in delegated_resource:
            bandwidth = r.get("frozen_balance_for_bandwidth", 0)
            bandwidth_expiry = r.get("expire_time_for_bandwidth", 0) # milliseconds since epoch
            energy = r.get("frozen_balance_for_energy", 0)
            energy_expiry = r.get("expire_time_for_energy", 0) # milliseconds since epoch
            
            delegate_infos.append(DelegateInfo(
                to_address=acc,
                bandwidth=bandwidth,
                energy=energy,
                bandwidth_expiry=datetime.fromtimestamp(bandwidth_expiry / 1000) if bandwidth_expiry > 0 else None,
                energy_expiry=datetime.fromtimestamp(energy_expiry / 1000) if energy_expiry > 0 else None
            ))
    return delegate_infos

async def claim_expired_resources(client: AsyncClient, priv_key: bytes, address: str, to_address: str, resource_type: Literal["BANDWIDTH", "ENERGY"], sun_amount: int) -> bool:
    url = "https://api.trongrid.io/wallet/undelegateresource"
    payload = {
        "owner_address": address,
        "receiver_address": to_address,
        "resource": resource_type,
        "balance": sun_amount,
        "visible": True
    }

    try:
        response = await client.post(url, json=payload)
        response.raise_for_status()
    except Exception as e:
        logger.log(f"Create undelegate resource transaction failed: {e}", logger.LogLevel.ERROR)
        return False
    
    await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

    transaction = sign_transaction(response.json(), priv_key)

    url = "https://api.trongrid.io/wallet/broadcasttransaction"
    try:
        response = await client.post(url, json=transaction)
        response.raise_for_status()
    except Exception as e:
        logger.log(f"Broadcast transaction failed: {e}", logger.LogLevel.ERROR)
        return False

    await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

    resp : dict = response.json()
    if not resp.get("result", False):
        logger.log(f"Transaction failed: {resp}", logger.LogLevel.ERROR)
        return False
    return True