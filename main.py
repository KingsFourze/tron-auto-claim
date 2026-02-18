import asyncio, sys, json
from httpx import AsyncClient
from datetime import datetime

from lib.tron import Tron, DelegateInfo
from lib import logger
from config import KEEP_DELEGATE_ADDRESS

async def check_and_claim_resources(tron: Tron, curr_epoch: float, delegate_info: DelegateInfo):
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
        await tron.claim_expired_resources(delegate_info.to_address, "BANDWIDTH", delegate_info.bandwidth_sun)

    # claim energy if it's expired
    if delegate_info.energy_sun > 0 and (delegate_info.energy_expiry is None or delegate_info.energy_expiry.timestamp() < curr_epoch):
        logger.log("  Energy expired, claiming...", logger.LogLevel.INFO)
        await tron.claim_expired_resources(delegate_info.to_address, "ENERGY", delegate_info.energy_sun)

async def main():
    if len(sys.argv) != 2:
        logger.log("Usage: python main.py <private_key_hex>", logger.LogLevel.WARNING)
        sys.exit(1)

    PRIVATE_KEY_HEX = sys.argv[1]
    PRIVATE_KEY = bytes.fromhex(PRIVATE_KEY_HEX)

    tron = Tron(PRIVATE_KEY)
    logger.log(f"Address: {tron.address}", logger.LogLevel.INFO)

    account_info = await tron.get_account_info()
    if account_info is None:
        logger.log("Failed to fetch account info. Exiting.", logger.LogLevel.ERROR)
        sys.exit(1)
    logger.log(f"   Balance: {account_info.balance_trx} TRX", logger.LogLevel.INFO)
    logger.log(f"   Power: {account_info.staked_resources.power} | Voted: {account_info.staked_resources.voted_power} | Leaves: {account_info.staked_resources.power - account_info.staked_resources.voted_power}", logger.LogLevel.INFO)

    reward_trx = await tron.get_reward_info()
    logger.log(f"   Reward: {reward_trx} TRX", logger.LogLevel.INFO)
    logger.log(f"   Latest Withdraw Time: {account_info.latest_withdraw_time}", logger.LogLevel.INFO)

    logger.log("", logger.LogLevel.INFO)

    if reward_trx > 0 and account_info.latest_withdraw_time is not None and datetime.now().timestamp() - account_info.latest_withdraw_time.timestamp() > 24 * 60 * 60:
        logger.log("Reward available and last withdraw was more than 24 hours ago, claiming reward...", logger.LogLevel.INFO)
        success = await tron.withdraw_rewards()
        if success:
            logger.log("Reward claimed successfully.", logger.LogLevel.INFO)
            account_info.balance_trx += reward_trx
        else:
            logger.log("Failed to claim reward.", logger.LogLevel.WARNING)

    delegate_info = await tron.get_delegate_info()
    if delegate_info is None or len(delegate_info) == 0:
        return
    for info in delegate_info:
        await check_and_claim_resources(tron, datetime.now().timestamp(), info)

if __name__ == "__main__":
    asyncio.run(main())