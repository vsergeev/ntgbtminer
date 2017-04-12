# ntgbtminer - vsergeev at gmail
# No Thrils GetBlockTemplate Bitcoin Miner
#
# This is mostly a demonstration of the GBT protocol.
# It mines at a measly 150 KHashes/sec on my computer
# but with a whole lot of spirit ;)
#

import urllib2
import base64
import json
import hashlib
import struct
import random
import time

# JSON-HTTP RPC Configuration
# This will be particular to your local ~/.bitcoin/bitcoin.conf

### Edit me! v
RPC_URL     = "http://127.0.0.1:8332"
RPC_USER    = "bitcoinrpc"
RPC_PASS    = ""
### Edit me! ^

################################################################################
# Bitcoin Daemon JSON-HTTP RPC
################################################################################

def rpc(method, params=None):
    rpc_id = random.getrandbits(32)

    callstr = json.dumps({"id": rpc_id, "method": method, "params": params})

    authstr = base64.encodestring('%s:%s' % (RPC_USER, RPC_PASS)).strip()

    request = urllib2.Request(RPC_URL)
    request.add_header("Authorization", "Basic %s" % authstr)
    request.add_data(callstr)
    f = urllib2.urlopen(request)
    response = json.loads(f.read())

    if response['id'] != rpc_id:
        raise ValueError("invalid response id!")
    elif response['error'] != None:
        raise ValueError("rpc error: %s" % json.dumps(response['error']))

    return response['result']

################################################################################
# Bitcoin Daemon RPC Call Wrappers
################################################################################

def rpc_getblocktemplate():
    try: return rpc("getblocktemplate", [{}])
    except ValueError: return {}

def rpc_submitblock(block_submission):
    try: return rpc("submitblock", [block_submission])
    except ValueError: return {}

# For unittest purposes:

def rpc_getblock(block_id):
    try: return rpc("getblock", [block_id])
    except ValueError: return {}

def rpc_getrawtransaction(transaction_id):
    try: return rpc("getrawtransaction", [transaction_id])
    except ValueError: return {}

################################################################################
# Representation Conversion Utility Functions
################################################################################

# Convert an unsigned integer to a little endian ASCII Hex
def int2lehex(x, width):
    if width == 1: return "%02x" % x
    elif width == 2: return "".join(["%02x" % ord(c) for c in struct.pack("<H", x)])
    elif width == 4: return "".join(["%02x" % ord(c) for c in struct.pack("<L", x)])
    elif width == 8: return "".join(["%02x" % ord(c) for c in struct.pack("<Q", x)])

# Convert an unsigned integer to little endian varint ASCII Hex
def int2varinthex(x):
    if x < 0xfd: return "%02x" % x
    elif x <= 0xffff: return "fd" + int2lehex(x, 2)
    elif x <= 0xffffffff: return "fe" + int2lehex(x, 4)
    else: return "ff" + int2lehex(x, 8)

# Convert a binary string to ASCII Hex
def bin2hex(s):
    h = ""
    for c in s:
        h += "%02x" % ord(c)
    return h

# Convert an ASCII Hex string to a binary string
def hex2bin(s):
    b = ""
    for i in range(len(s)/2):
        b += chr(int(s[2*i : 2*i + 2], 16))
    return b

# Convert a Base58 Bitcoin address to its Hash-160 ASCII Hex
def bitcoinaddress2hash160(s):
    table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    x = 0
    s = s[::-1]
    for i in range(len(s)):
        x += (58**i)*table.find(s[i])

    # Convert number to ASCII Hex string
    x = "%050x" % x
    # Discard 1-byte network byte at beginning and 4-byte checksum at the end
    return x[2:50-8]

################################################################################
# Transaction coinbase height encoding
################################################################################

# Create a coinbase transaction
#
# Arguments:
#       height:    the height of the mined block
#
# Return the height encoded as per BIP 34
# See: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
def encode_coinbase_height(n, min_size = 1):
  	s = bytearray(b'\1')

  	while n > 127:
  		s[0] += 1
  		s.append(n % 256)
  		n //= 256

  	s.append(n)

  	while len(s) < min_size + 1:
  		s.append(0)
  		s[0] += 1

  	return bytes(s)

################################################################################
# Transaction Coinbase and Hashing Functions
################################################################################

# Create a coinbase transaction
#
# Arguments:
#       coinbase_script:    (hex string) arbitrary script
#       address:            (base58 string) bitcoin address
#       value:              (unsigned int) value
#
# Returns transaction data in ASCII Hex
def tx_make_coinbase(coinbase_script, address, value, height):
    # See https://en.bitcoin.it/wiki/Transaction
    
    coinbase_script = bin2hex(encode_coinbase_height(height)) + coinbase_script

    # Create a pubkey script
    # OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
    pubkey_script = "76" + "a9" + "14" + bitcoinaddress2hash160(address) + "88" + "ac"

    tx = ""
    # version
    tx += "01000000"
    # in-counter
    tx += "01"
    # input[0] prev hash
    tx += "0"*64
    # input[0] prev seqnum
    tx += "ffffffff"
    # input[0] script len
    tx += int2varinthex(len(coinbase_script)/2)
    # input[0] script
    tx += coinbase_script
    # input[0] seqnum
    tx += "ffffffff"
    # out-counter
    tx += "01"
    # output[0] value (little endian)
    tx += int2lehex(value, 8)
    # output[0] script len
    tx += int2varinthex(len(pubkey_script)/2)
    # output[0] script
    tx += pubkey_script
    # lock-time
    tx += "00000000"

    return tx

# Compute the SHA256 Double Hash of a transaction
#
# Arguments:
#       tx:    (hex string) ASCII Hex transaction data
#
# Returns a SHA256 double hash in big endian ASCII Hex
def tx_compute_hash(tx):
    h1 = hashlib.sha256(hex2bin(tx)).digest()
    h2 = hashlib.sha256(h1).digest()
    return bin2hex(h2[::-1])

# Compute the Merkle Root of a list of transaction hashes
#
# Arguments:
#       tx_hashes:    (list) ASCII Hex transaction hashes
#
# Returns a SHA256 double hash in big endian ASCII Hex
def tx_compute_merkle_root(tx_hashes):
    # Convert each hash into a binary string
    for i in range(len(tx_hashes)):
        # Reverse the hash from big endian to little endian
        tx_hashes[i] = hex2bin(tx_hashes[i])[::-1]

    # Iteratively compute the merkle root hash
    while len(tx_hashes) > 1:
        # Duplicate last hash if the list is odd
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1][:])

        tx_hashes_new = []
        for i in range(len(tx_hashes)/2):
            # Concatenate the next two
            concat = tx_hashes.pop(0) + tx_hashes.pop(0)
            # Hash them
            concat_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
            # Add them to our working list
            tx_hashes_new.append(concat_hash)
        tx_hashes = tx_hashes_new

    # Format the root in big endian ascii hex
    return bin2hex(tx_hashes[0][::-1])

################################################################################
# Block Preparation Functions
################################################################################

# Form the block header
#
# Arguments:
#       block:      (dict) block data in dictionary
#
# Returns a binary string
def block_form_header(block):
    header = ""

    # Version
    header += struct.pack("<L", block['version'])
    # Previous Block Hash
    header += hex2bin(block['previousblockhash'])[::-1]
    # Merkle Root Hash
    header += hex2bin(block['merkleroot'])[::-1]
    # Time
    header += struct.pack("<L", block['curtime'])
    # Target Bits
    header += hex2bin(block['bits'])[::-1]
    # Nonce
    header += struct.pack("<L", block['nonce'])

    return header

# Compute the Raw SHA256 Double Hash of a block header
#
# Arguments:
#       header:    (string) binary block header
#
# Returns a SHA256 double hash in big endian binary
def block_compute_raw_hash(header):
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]

# Convert block bits to target
#
# Arguments:
#       bits:       (string) compressed target in ASCII Hex
#
# Returns a target in big endian binary
def block_bits2target(bits):
    # Bits: 1b0404cb
    # 1b -> left shift of (0x1b - 3) bytes
    # 0404cb -> value
    shift = ord(hex2bin(bits[0:2])[0]) - 3
    value = hex2bin(bits[2:])

    # Shift value to the left by shift (big endian)
    target = value + "\x00"*shift
    # Add leading zeros (big endian)
    target = "\x00"*(32-len(target)) + target

    return target

# Check if a block header hash meets the target hash
#
# Arguments:
#       block_hash: (string) block hash in big endian binary
#       target:     (string) target in big endian binary
#
# Returns true if header_hash meets target, false if it does not.
def block_check_target(block_hash, target_hash):
    # Header hash must be strictly less than or equal to target hash
    for i in range(len(block_hash)):
        if ord(block_hash[i]) == ord(target_hash[i]):
            continue
        elif ord(block_hash[i]) < ord(target_hash[i]):
            return True
        else:
            return False

# Format a solved block into the ASCII Hex submit format
#
# Arguments:
#       block:      (dict) block
#
# Returns block in ASCII Hex submit format
def block_make_submit(block):
    subm = ""

    # Block header
    subm += bin2hex(block_form_header(block))
    # Number of transactions as a varint
    subm += int2varinthex(len(block['transactions']))
    # Concatenated transactions data
    for tx in block['transactions']:
        subm += tx['data']

    return subm

################################################################################
# Mining Loop
################################################################################

# Mine a block
#
# Arguments:
#       block_template:     (dict) block template
#       coinbase_message:   (string) binary string for coinbase script
#       extranonce_start:   (int) extranonce for coinbase script
#       address:            (string) base58 reward bitcoin address
#
# Optional Arguments:
#       timeout:            (False / int) timeout in seconds to give up mining
#       debugnonce_start:   (False / int) nonce start for testing purposes
#
# Returns tuple of (solved block, hashes per second) on finding a solution,
# or (None, hashes per second) on timeout or nonce exhaustion.
def block_mine(block_template, coinbase_message, extranonce_start, address, timeout=False, debugnonce_start=False):
    # Add an empty coinbase transaction to the block template
    coinbase_tx = {}
    block_template['transactions'].insert(0, coinbase_tx)
    # Add a nonce initialized to zero to the block template
    block_template['nonce'] = 0

    # Compute the target hash
    target_hash = block_bits2target(block_template['bits'])

    # Mark our mine start time
    time_start = time.clock()

    # Initialize our running average of hashes per second
    hps_list = []

    # Loop through the extranonce
    extranonce = extranonce_start
    while extranonce <= 0xffffffff:

        # Update the coinbase transaction with the extra nonce
        coinbase_script = coinbase_message + int2lehex(extranonce, 4)
        coinbase_tx['data'] = tx_make_coinbase(coinbase_script, address, block_template['coinbasevalue'], block_template['height'])
        coinbase_tx['hash'] = tx_compute_hash(coinbase_tx['data'])

        # Recompute the merkle root
        tx_hashes = [tx['hash'] for tx in block_template['transactions']]
        block_template['merkleroot'] = tx_compute_merkle_root(tx_hashes)

        # Reform the block header
        block_header = block_form_header(block_template)

        time_stamp = time.clock()

        # Loop through the nonce
        nonce = 0 if debugnonce_start == False else debugnonce_start
        while nonce <= 0xffffffff:
            # Update the block header with the new 32-bit nonce
            block_header = block_header[0:76] + chr(nonce & 0xff) + chr((nonce >> 8) & 0xff) + chr((nonce >> 16) & 0xff) + chr((nonce >> 24) & 0xff)
            # Recompute the block hash
            block_hash = block_compute_raw_hash(block_header)

            # Check if it the block meets the target target hash
            if block_check_target(block_hash, target_hash):
                block_template['nonce'] = nonce
                block_template['hash'] = bin2hex(block_hash)
                hps_average = 0 if len(hps_list) == 0 else sum(hps_list)/len(hps_list)
                return (block_template, hps_average)

            # Lightweight benchmarking of hashes / sec and timeout check
            if nonce > 0 and nonce % 1000000 == 0:
                time_elapsed = time.clock() - time_stamp
                hps_list.append(1000000.0 / time_elapsed)
                time_stamp = time.clock()

                # If our mine time expired, return none
                if timeout != False and (time_stamp - time_start) > timeout:
                    hps_average = 0 if len(hps_list) == 0 else sum(hps_list)/len(hps_list)
                    return (None, hps_average)

            nonce += 1
        extranonce += 1

    # If we ran out of extra nonces, return none
    hps_average = 0 if len(hps_list) == 0 else sum(hps_list)/len(hps_list)
    return (None, hps_average)

################################################################################
# Standalone Bitcoin Miner, Single-threaded
################################################################################

def standalone_miner(coinbase_message, address):
    while True:
        print "Mining new block template..."
        mined_block, hps = block_mine(rpc_getblocktemplate(), coinbase_message, 0, address, timeout=60)
        print "Average Mhash/s: %.4f\n" % (hps / 1000000.0)

        if mined_block != None:
            print "Solved a block! Block hash:", mined_block['hash']
            submission = block_make_submit(mined_block)
            print "Submitting:", submission, "\n"
            rpc_submitblock(submission)

if __name__ == "__main__":
    standalone_miner(bin2hex("Hello from vsergeev!"), "15PKyTs3jJ3Nyf3i6R7D9tfGCY1ZbtqWdv")