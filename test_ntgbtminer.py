from ntgbtminer import *
import unittest

################################################################################
# Unit Tests
################################################################################

class TestConversions(unittest.TestCase):
    def test_int2lehex(self):
        self.assertEqual(int2lehex(0x1a, 1), "1a")
        self.assertEqual(int2lehex(0x1a2b, 2), "2b1a")
        self.assertEqual(int2lehex(0x1a2b3c4d, 4), "4d3c2b1a")
        self.assertEqual(int2lehex(0x1a2b3c4d5e6f7a8b, 8), "8b7a6f5e4d3c2b1a")

    def test_int2varinthex(self):
        self.assertEqual(int2varinthex(0x1a), "1a")
        self.assertEqual(int2varinthex(0x1a2b), "fd2b1a")
        self.assertEqual(int2varinthex(0x1a2b3c), "fe3c2b1a00")
        self.assertEqual(int2varinthex(0x1a2b3c4d), "fe4d3c2b1a")
        self.assertEqual(int2varinthex(0x1a2b3c4d5e), "ff5e4d3c2b1a000000")

    def test_bin2hex(self):
        self.assertEqual(bin2hex("\x00\x01\xab\xcdA"), "0001abcd41")

    def test_hex2bin(self):
        self.assertEqual(hex2bin("0001abcd41"), "\x00\x01\xab\xcdA")

    def bitcoinaddress2hash160(self):
        self.assertEqual(bitcoinaddress2hash160("14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"), "27a1f12771de5cc3b73941664b2537c15316be43")

class TestTransaction(unittest.TestCase):
    def test_hash(self):
        # Source Data
        #   Block ID 000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7
        #   Transaction ID 05f1f0c7fc25005e7c6e56805130b4d540125a8d09f81ec3da621f99ee5d15c1

        # Test Vector is coinbase transaction hash
        test_vector = "05f1f0c7fc25005e7c6e56805130b4d540125a8d09f81ec3da621f99ee5d15c1"

        # Coinbase transaction data
        tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503ef98030400001059124d696e656420627920425443204775696c640800000037000011caffffffff01a0635c95000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000"

        self.assertEqual(tx_compute_hash(tx), test_vector)

    def test_make_coinbase(self):
        # Source Data
        #   Block ID 000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7
        #   Transaction ID 05f1f0c7fc25005e7c6e56805130b4d540125a8d09f81ec3da621f99ee5d15c1

        # Test Vector is coinbase transaction data
        test_vector = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503ef98030400001059124d696e656420627920425443204775696c640800000037000011caffffffff01a0635c95000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000"

        # Parameters to form coinbase transaction
        coinbase_script = "03ef98030400001059124d696e656420627920425443204775696c640800000037000011ca"
        address = "14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"
        value = 2505860000

        self.assertEqual(tx_make_coinbase(coinbase_script, address, value), test_vector)

    def test_merkle_root(self):
        # Source Data
        #   Block ID 000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7
        block = rpc_getblock("000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7")

        # Test Vector is block Merkle Root
        test_vector = block['merkleroot']

        # Transaction hash list
        tx_hashes = block['tx']

        self.assertEqual(tx_compute_merkle_root(tx_hashes), test_vector)

class TestBlock(unittest.TestCase):
    def test_bits2target(self):
        # Source Data
        #   Bits    1a01aa3d
        #   Target  00000000000001aa3d0000000000000000000000000000000000000000000000

        bits = "1a01aa3d"
        vector = "00000000000001aa3d0000000000000000000000000000000000000000000000"
        self.assertEqual(bin2hex(block_bits2target(bits)), vector)

        # Source Data
        #   Bits    1b0404cb
        #   Target  00000000000404cb000000000000000000000000000000000000000000000000

        bits = "1b0404cb"
        vector = "00000000000404cb000000000000000000000000000000000000000000000000"
        self.assertEqual(bin2hex(block_bits2target(bits)), vector)

    def test_block_hash(self):
        # Source Data
        #   Block ID 000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7
        block = rpc_getblock("000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7")

        # Test Vector is block hash
        test_vector = block['hash']
        # Copy time key to curtime key to make block look like block template
        block['curtime'] = block['time']

        # Check block hash
        header = block_form_header(block)
        header_hash = bin2hex(block_compute_raw_hash(header))
        self.assertEqual(header_hash, test_vector)

        # Check block hash meets or fails various targets
        header_hash = block_compute_raw_hash(header)
        target_hash = block_bits2target(block['bits'])
        self.assertEqual(block_check_target(header_hash, target_hash), True)
        header_hash = '\x01' + header_hash[1:]
        self.assertEqual(block_check_target(header_hash, target_hash), False)
        header_hash = '\x00'*6 + '\x02' + header_hash[8:]
        self.assertEqual(block_check_target(header_hash, target_hash), False)
        header_hash = '\x00'*6 + '\x01' + header_hash[8:]
        self.assertEqual(block_check_target(header_hash, target_hash), True)
        header_hash = '\x00'*6 + '\x01\xaa\x3c' + header_hash[10:]
        self.assertEqual(block_check_target(header_hash, target_hash), True)
        header_hash = '\x00'*6 + '\x01\xaa\x3d' + header_hash[10:]
        self.assertEqual(block_check_target(header_hash, target_hash), False)

    def test_block_mine(self):
        # Source Data
        #   Block ID 000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7
        block = rpc_getblock("000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7")

        # Manipulate the transactions in real block to look like a block template
        block['transactions'] = []
        for i in range(1, len(block['tx'])):
            tx = {'hash': block['tx'][i], 'data': 'abc'}
            block['transactions'].append(tx)

        # Setup generation transaction parameters with same extra nonce start as the mined black
        coinbase_message = "03ef98030400001059124d696e656420627920425443204775696c640800000037"
        extra_nonce_start = 0xca110000
        address = "14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"
        block['coinbasevalue'] = 2505860000
        # Copy time key to curtime key to make block look like block template
        block['curtime'] = block['time']
        # Clear block hash
        block['hash' ] = ""

        # Mine
        (mined_block, hps) = block_mine(block, coinbase_message, extra_nonce_start, address, timeout=60, debugnonce_start=2315460000)

        # Test vector is actual block hash
        test_vector = "000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7"

        self.assertEqual(mined_block['hash'], test_vector)

if __name__ == "__main__":
    unittest.main()

