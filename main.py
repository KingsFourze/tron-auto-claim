import asyncio, sys
from httpx import AsyncClient
from datetime import datetime

from lib.tron import calc_address_from_priv_key, get_delegate_info, claim_expired_resources, DelegateInfo
from lib import logger
from config import KEEP_DELEGATE_ADDRESS

async def check_and_claim_resources(client: AsyncClient, priv_key: bytes, address: str, curr_epoch: float, delegate_info: DelegateInfo):
    # print delegate info
    logger.log("", logger.LogLevel.INFO)
    logger.log(f"Delegated to: {delegate_info.to_address}", logger.LogLevel.INFO)
    if delegate_info.bandwidth_sun > 0:
        logger.log(f"  Bandwidth: {delegate_info.bandwidth_sun} (expires at {delegate_info.bandwidth_expiry})", logger.LogLevel.INFO)
    if delegate_info.energy_sun > 0:
        logger.log(f"  Energy: {delegate_info.energy_sun} (expires at {delegate_info.energy_expiry})", logger.LogLevel.INFO)

    # check if this delegate is in the keep list
    if delegate_info.to_address in KEEP_DELEGATE_ADDRESS:
        logger.log("  Skipping claim for this delegate as it's in the keep list.", logger.LogLevel.INFO)
        return
    
    # claim bandwidth if it's expired
    if delegate_info.bandwidth_sun > 0 and (delegate_info.bandwidth_expiry is None or delegate_info.bandwidth_expiry.timestamp() < curr_epoch):
        logger.log("  Bandwidth expired, claiming...", logger.LogLevel.INFO)
        await claim_expired_resources(client, priv_key, address, delegate_info.to_address, "BANDWIDTH", delegate_info.bandwidth_sun)

    # claim energy if it's expired
    if delegate_info.energy_sun > 0 and (delegate_info.energy_expiry is None or delegate_info.energy_expiry.timestamp() < curr_epoch):
        logger.log("  Energy expired, claiming...", logger.LogLevel.INFO)
        await claim_expired_resources(client, priv_key, address, delegate_info.to_address, "ENERGY", delegate_info.energy_sun)

async def main():
    if len(sys.argv) != 2:
        logger.log("Usage: python main.py <private_key_hex>", logger.LogLevel.WARNING)
        sys.exit(1)

    PRIVATE_KEY_HEX = sys.argv[1]
    PRIVATE_KEY = bytes.fromhex(PRIVATE_KEY_HEX)

    address = calc_address_from_priv_key(PRIVATE_KEY)
    print(f"Address: {address}")

    current_epoch = datetime.now().timestamp()
    async with AsyncClient() as client:
        delegate_info = await get_delegate_info(client, address)
        if delegate_info is None or len(delegate_info) == 0:
            return
        
        for info in delegate_info:
            await check_and_claim_resources(client, PRIVATE_KEY, address, current_epoch, info)

if __name__ == "__main__":
    asyncio.run(main())