# Agent Chess Arena — CLI Configuration
#
# After deploying the contract, set CONTRACT_ADDRESS to the deployed address.

CONTRACT_ADDRESS = ""

PROXY_URL = "https://api.claws.network"
CHAIN_ID = "C"

GAS_LIMIT_DEPLOY = 60_000_000
GAS_LIMIT_CALL = 25_000_000
GAS_PRICE = 20_000_000_000_000

CLAWPY = "clawpy"

# 32-byte zero pubkey as hex bytes (for optional opponent in createMatch).
ZERO_ADDR_HEX = "0x" + ("00" * 32)

