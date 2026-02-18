# TRON Auto Claim
A auto claimer made for TRON. 

## Usage
1. Add the addresses, which you're want to keep delegate, into `config.py`.
    ```
    # for example (these is just fake addresses):
    KEEP_DELEGATE_ADDRESS = ["TABCDEFGHIJKLMNOPQRSTUVWX", "T1234567890ABCDEFGHIJKLMN"]
    ```
2. Set the following script to cron job to do it regularly.
    ```bash
    uv run main.py <private_key_hex>
    ```

## Functions
1. Print account balance, power infomation.
1. Withdraw reward from voting.
1. Print out all delegated to others resources and their expiry datetime.
1. Claim all expired delegate.