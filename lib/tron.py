import asyncio
from typing import Optional, Literal
import hashlib, base58
from Crypto.Hash import keccak
from coincurve import PrivateKey as CoincurvePrivateKey
from httpx import AsyncClient
from datetime import datetime

from . import logger

SUN_IN_TRX = 1_000_000

class StakedResourceInfo:
    def __init__(self):
        self.bandwidth_trx : int = 0
        self.delegated_bandwidth_trx : int = 0
        self.energy_trx : int = 0
        self.delegated_energy_trx : int = 0
        self.power : int = 0
        self.voted_power : int = 0

    def to_dict(self) -> dict:
        return {
            "bandwidth_trx": self.bandwidth_trx,
            "delegated_bandwidth_trx": self.delegated_bandwidth_trx,
            "energy_trx": self.energy_trx,
            "delegated_energy_trx": self.delegated_energy_trx,
            "power": self.power,
            "voted_power": self.voted_power
        }

class VoteInfo:
    def __init__(self, vote_address: str, vote_count: int):
        self.vote_address = vote_address
        self.vote_count = vote_count

    def to_dict(self) -> dict:
        return {
            "vote_address": self.vote_address,
            "vote_count": self.vote_count
        }

class AccountInfo:
    def __init__(self, address: str):
        self.address = address
        self.balance_trx : float = 0.0
        self.create_time : Optional[datetime] = None
        self.latest_opration_time : Optional[datetime] = None

        # total staked resources
        self.staked_resources = StakedResourceInfo()

        # votes and rewards
        self.latest_withdraw_time : Optional[datetime] = None
        self.votes : list[VoteInfo] = []

        # resources and delegations status
        self.latest_consume_time_bandwidth : Optional[datetime] = None
        self.latest_consume_free_time_bandwidth : Optional[datetime] = None
        self.latest_consume_time_energy : Optional[datetime] = None
        self.bandwidth_window_size : Optional[int] = None
        self.energy_window_size : Optional[int] = None

    def load_from_api_response(self, resp: dict):
        # convert from sun to trx
        self.balance_trx = round(resp.get("balance", 0) / SUN_IN_TRX, 6)

        # convert times from milliseconds since epoch to datetime
        self.create_time = datetime.fromtimestamp(resp["create_time"] / 1000) if "create_time" in resp else None
        self.latest_opration_time = datetime.fromtimestamp(resp["latest_opration_time"] / 1000) if "latest_opration_time" in resp else None
        self.latest_withdraw_time = datetime.fromtimestamp(resp["latest_withdraw_time"] / 1000) if "latest_withdraw_time" in resp else None

        # load resources
        frozen_v2 = resp.get("frozenV2", [])
        for f in frozen_v2:
            resource_type = f.get("type", "BANDWIDTH")
            amount = f.get("amount", 0)
            if resource_type == "BANDWIDTH":
                self.staked_resources.bandwidth_trx += int(round(amount / SUN_IN_TRX, 6))
            elif resource_type == "ENERGY":
                self.staked_resources.energy_trx += int(round(amount / SUN_IN_TRX, 6))

        # load votes
        votes = resp.get("votes", [])
        for v in votes:
            self.staked_resources.voted_power += v["vote_count"]
            self.votes.append(VoteInfo(v["vote_address"], v["vote_count"]))

        # load delegated resources (bandwidth)
        self.latest_consume_time_bandwidth = datetime.fromtimestamp(resp["latest_consume_time"] / 1000) if "latest_consume_time" in resp else None
        self.latest_consume_free_time_bandwidth = datetime.fromtimestamp(resp["latest_consume_free_time"] / 1000) if "latest_consume_free_time" in resp else None
        self.staked_resources.delegated_bandwidth_trx = int(round(resp.get("delegated_frozenV2_balance_for_bandwidth", 0) / SUN_IN_TRX, 6))
        self.staked_resources.bandwidth_trx += self.staked_resources.delegated_bandwidth_trx
        self.bandwidth_window_size = resp.get("net_window_size", 0)
        if resp.get("net_window_optimized", False):
            self.bandwidth_window_size = round(self.bandwidth_window_size / 1000, 3)

        # load delegated resources (energy)
        account_resource : dict = resp.get("account_resource", {})
        self.latest_consume_time_energy = datetime.fromtimestamp(account_resource["latest_consume_time_for_energy"] / 1000) if "latest_consume_time_for_energy" in account_resource else None
        self.staked_resources.delegated_energy_trx = int(round(account_resource.get("delegated_frozenV2_balance_for_energy", 0) / SUN_IN_TRX, 6))
        self.staked_resources.energy_trx += self.staked_resources.delegated_energy_trx
        self.energy_window_size = account_resource.get("energy_window_size", 0)
        if account_resource.get("net_window_optimized", False):
            self.energy_window_size = round(self.energy_window_size / 1000, 3)

        # calculate total power
        self.staked_resources.power += self.staked_resources.bandwidth_trx + self.staked_resources.energy_trx

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "balance_trx": self.balance_trx,
            "create_time": self.create_time.isoformat() if self.create_time else None,
            "latest_opration_time": self.latest_opration_time.isoformat() if self.latest_opration_time else None,
            "latest_withdraw_time": self.latest_withdraw_time.isoformat() if self.latest_withdraw_time else None,
            "staked_resources": self.staked_resources.to_dict() if self.staked_resources else None,
            "votes": [v.to_dict() for v in self.votes],
            "latest_consume_time_bandwidth": self.latest_consume_time_bandwidth.isoformat() if self.latest_consume_time_bandwidth else None,
            "latest_consume_free_time_bandwidth": self.latest_consume_free_time_bandwidth.isoformat() if self.latest_consume_free_time_bandwidth else None,
            "delegated_v2_for_bandwidth_trx": self.staked_resources.delegated_bandwidth_trx,
            "bandwidth_window_size": self.bandwidth_window_size,
            "latest_consume_time_energy": self.latest_consume_time_energy.isoformat() if self.latest_consume_time_energy else None,
            "delegated_v2_for_energy_trx": self.staked_resources.delegated_energy_trx,
            "energy_window_size": self.energy_window_size
        }

class DelegateInfo:
    def __init__(self, to_address: str, bandwidth: int, energy: int, bandwidth_expiry: Optional[datetime] = None, energy_expiry: Optional[datetime] = None):
        self.to_address = to_address
        self.bandwidth_sun = bandwidth
        self.energy_sun = energy
        self.bandwidth_expiry = bandwidth_expiry
        self.energy_expiry = energy_expiry

class Tron:
    def __init__(self, priv_key: bytes, api_host: str = "https://api.trongrid.io"):
        self.client = AsyncClient()
        self.api_host = api_host

        self.priv_key_byte = priv_key
        self.priv_key = CoincurvePrivateKey(priv_key)
        self.address = self.__calc_address_from_priv_key()

    # Internal method to calculate Tron address from private key
    def __calc_address_from_priv_key(self) -> str:
        pk = self.priv_key.public_key.format(compressed=False)[1:] # remove the 0x04 prefix for uncompressed keys

        h = keccak.new(digest_bits=256).update(pk).digest()
        address_bytes = b'\x41' + h[-20:] # Tron addresses start with 0x41
        tron_address = base58.b58encode_check(address_bytes).decode("utf-8")
        return tron_address

    # Method to sign a transaction
    def sign_transaction(self, transaction: dict) -> dict:
        raw_data = bytes.fromhex(transaction["raw_data_hex"])
        raw_data_hash = hashlib.sha256(raw_data).digest()

        raw_signature = self.priv_key.sign_recoverable(raw_data_hash, hasher=None)
        normalized_signature = raw_signature.hex()[:64] + raw_signature.hex()[64:].rjust(64, '0')
        
        transaction["signature"] = [normalized_signature]
        return transaction
    
    async def get_account_info(self) -> Optional[AccountInfo]:
        try:
            url = f"{self.api_host}/wallet/getaccount"
            payload = {
                "address": self.address,
                "visible": True
            }
            response = await self.client.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logger.log(f"Error fetching account info for address {self.address}: {e}", logger.LogLevel.ERROR)
            return None
        
        await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

        resp = response.json()


        account_info = AccountInfo(self.address)
        account_info.load_from_api_response(resp)
        return account_info
    
    async def get_reward_info(self) -> int:
        try:
            url = f"{self.api_host}/wallet/getReward"
            payload = {
                "address": self.address,
                "visible": True
            }
            response = await self.client.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logger.log(f"Error fetching reward info for address {self.address}: {e}", logger.LogLevel.ERROR)
            return 0
        
        await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

        resp = response.json()
        reward_sun = resp.get("reward", 0)
        reward_trx = round(reward_sun / SUN_IN_TRX, 6)
        return reward_trx
    
    async def get_delegate_info(self) -> list[DelegateInfo]:
        # Get delegated accounts for the address
        try:
            url = f"{self.api_host}/wallet/getdelegatedresourceaccountindexv2"
            payload = {
                "value": self.address,
                "visible": True
            }

            response = await self.client.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logger.log(f"Error fetching delegate info for address {self.address}: {e}", logger.LogLevel.ERROR)
            return None
        
        await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits
        
        # Process response to get delegated accounts
        resp = response.json()
        if "toAccounts" not in resp:
            logger.log(f"No delegate accounts found for {self.address}", logger.LogLevel.INFO)
            return []
        delegate_accounts : list[str] = resp["toAccounts"]

        # For each delegated account, fetch the delegated resource info
        delegate_infos : list[DelegateInfo] = []
        url = f"{self.api_host}/wallet/getdelegatedresourcev2"
        payload = {
            "fromAddress": self.address,
            "visible": True
        }
        for acc in delegate_accounts:
            payload["toAddress"] = acc
            try:
                response = await self.client.post(url, json=payload)
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
    
    async def withdraw_rewards(self) -> bool:
        url = f"{self.api_host}/wallet/withdrawbalance"
        payload = {
            "owner_address": self.address,
            "visible": True
        }

        try:
            response = await self.client.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logger.log(f"Create withdraw reward transaction failed: {e}", logger.LogLevel.ERROR)
            return False
        
        await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

        transaction = self.sign_transaction(response.json())

        url = f"{self.api_host}/wallet/broadcasttransaction"
        try:
            response = await self.client.post(url, json=transaction)
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

    async def claim_expired_resources(self, to_address: str, resource_type: Literal["BANDWIDTH", "ENERGY"], sun_amount: int) -> bool:
        url = f"{self.api_host}/wallet/undelegateresource"
        payload = {
            "owner_address": self.address,
            "receiver_address": to_address,
            "resource": resource_type,
            "balance": sun_amount,
            "visible": True
        }

        try:
            response = await self.client.post(url, json=payload)
            response.raise_for_status()
        except Exception as e:
            logger.log(f"Create undelegate resource transaction failed: {e}", logger.LogLevel.ERROR)
            return False
        
        await asyncio.sleep(0.5) # sleep for a bit to avoid hitting rate limits

        transaction = self.sign_transaction(response.json())

        url = f"{self.api_host}/wallet/broadcasttransaction"
        try:
            response = await self.client.post(url, json=transaction)
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