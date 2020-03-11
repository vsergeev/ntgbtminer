import ntgbtminer
import unittest


################################################################################
# Test Vectors
################################################################################

# rpc_getblock("000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7")
block_vector = {
    "hash": "000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7",
    "confirmations": 385277,
    "strippedsize": 149027,
    "size": 149027,
    "weight": 596108,
    "height": 235759,
    "version": 2,
    "versionHex": "00000002",
    "merkleroot": "3b135862ce5db3fa99836afd8b544e6385c5215cd68034227ced81caea0e961e",
    "tx": [
        "05f1f0c7fc25005e7c6e56805130b4d540125a8d09f81ec3da621f99ee5d15c1",
        "d7fa994cf346c7dc7495beeca3a46a6a722d58afedad8dfeaf175306eb2fe366",
        "8ab9df7e4f6319ce50c93b2bbaffab1794b133078b3ca6222bdcfe392d8b91fe",
        "fe91d70cdfff82d6a6b240d3a6ecfc6b132574c03fce3db2f0452b6607cb676c",
        "7fdcced2c5de242059bcaaf90d67961f618fef63e6ecdecb01a105a01644fd28",
        "00bb80d5600f76e98128c3f709c31e477482d6a8899134dadcdcf3b1e6a8c58c",
        "c3df04a49dd6e545c1751f306dcbd4c02309f3ceeb30eb2534ff9e803b43598f",
        "0d4588410b9ecd71af6e217a05c5ea3ee04a5e12d407ac8a45b8e0536c4f584b",
        "90e37b9ccae6c94f3c53c8a0935884a82c53fb7034eee86cecb851a558fb95b9",
        "dd01b1121d5f94bfc57ea228138c329ab7fe559a69169fcf4365696ae5973571",
        "2d1db481c0614eae6383812a37d755e1a86588cfb9d70e27e37c3cc3f34e36e6",
        "7097b212675ce5dc53d2420c520fa6f41237dcc3b9b920c3d72de3c7e3499d02",
        "a3a881345767766be4044286cad9ed09ee5cc5be62f5dfe44ae9f82560d7dd32",
        "a5de8daea23cb93213151721f322198823d84c4088f28f09a5fe318a3cef3c2a",
        "a06ae0f58a711bd76232869837508b0384a65560cb92d1f657b084af2a6a0a4f",
        "e104574aabc80eb79266e2f61af74079053a84d9652d92b0ae670bb520dec5db",
        "880dccc12f181a8760161156e08fa97667fedd30f68adab102bcaf1bb185fadc",
        "e2be8d49c49038a0b7f889d14750cc78857ebf7de9b078896a759ecc9922d3f5",
        "5a59a54f3c7280af597f7bf74e66b4e6ab4c33c02a8752e7d6c6ed73bf562743",
        "76313cfed9625dc784b5abc0740c446700d8646c815a6c86739bd77b7f39158e",
        "e94952413cda1f97f3b62932f510c5979dc72d1f3275f9f517c65d829384032b",
        "1e256deb9934b213787ea353df6c562ecb67ce613cc35898bbd3841820cd3f46",
        "44b33084838e6768393e065d61f52b0c1d6eea43d957495e58ba493bcf19b7ab",
        "b31e0c47401ad39a3c2fa1ed60712966cb19a5cd8c6e7e9ad8843e442b6dd5b4",
        "4bba5d9c1ff8fcdc2e3c5fd4410e7505b675a52d52d2ee58dea482801bfff35d",
        "684fb5a66b1448e21be946b0fd3970a682e0a0c367ac6056799e75b7ab252e3b",
        "acb7e6f926b17aa6ec1b246f0466c465bb1e77acf6ce26e19dad0d4f7b9c9abc",
        "03432c128dfe8a802d5887dad6702f5186fe6e77f13e194192e9a8ba031b3a77",
        "e65332801ea160dbc14d395e9e1de715b79815368747563b2f9f95fef62cc07c",
        "290d5478ac55951285342830cad2329d2b168900bf08c059db6558ec5e8c53ba",
        "7da5a488139cf4eb3cfbbd9b68cfb011bbf71ce36f6b6ed0044488d813aae7f4",
        "ff8956c6cca55dda428bb79a669d2cc36dd8fa7b795defd8b09e1b2f9cae278f",
        "45a8c45a49620a69c67d69c7afcb3e82bd50a5fe338cad5d5c85dfb7cc23e976",
        "4c1c8ff2333dd3de55ab5e943e5475290eccc3c4708bd937e841c686f353626a",
        "ee40dbf876e07c35bc840624d8c1a2a5552d2d3a44351914b6f98194f18d6d4a",
        "13402acacbcc005ea633f7c70ee6d9f8c93026447bb5fbdc82108bfd5bce25df",
        "62db32fce1781e2d3e9335c816e4738abd339a360253f86ea616fa113cb08c37",
        "a415ee013c399fadc3ffb182ed5e238257ae0b4ff20ca64b85276b7c38dad2e6",
        "9445e2dcf64c9b71be6c70ed4c6d404f13f3bf25b7efcc601a66cef6d85ccb15",
        "1adbfc94c0c7b3d1917353335915240cc6dfde90e823f6aeedcc8f4877443280",
        "4355f205ab9208f59a9806878596e1fdd0137c10d325d4af02ccbdd23b2a2540",
        "dfa76dbc7ec380fa6fbf77735895c8cb559c1a556341a196683aa4cfcf4bc3d8",
        "f7c5435924d8ba3f6e9f2592304039a0313b35e2be56da153ec8d8eef63d2ac1",
        "90ed549c161d9db4eac5e92363c55a83f15e54579c82731dbd58f4822bdf5c27",
        "cc7a22d0e4150542cb5182d1fe6f0468b243bccdbcacc5d35a4f15dbe8a65fae",
        "fb8f06804b5d0ce5760b467d5dc3312e22421c9f7f63dd62187163c346ef2491",
        "1d746f8e18b3f4af6ebc84844790dbe76b6978830d38e0dfa2041ec3d54795fa",
        "8823234403dcf8d36700a05ffb17d417ecd5d4586c29ad5fcab3dc4ea46c5447",
        "67e48c6d87ac936eaae5c5530d1b960a920eb38ae639a44ef831bc3415c276c8",
        "c333cdd6051cd398a055e541f97a6e1dabd1493434eb10cb6c213d642a0b68f5",
        "4b2ddcd5c0797e3be921d6fb0c59244df20e2139db64f36ece903951fef34a70",
        "98fd3a1aef5349f1cf063cd4d49dfd24a72d6d2977f318f466c953ae5ee2ad10",
        "7b03a56c004460a093bedabd0301366f86ed2c507298bd7d2fb85dbb75dfab58",
        "c40479b737fa88aed0f83da991ff9caf3ba9873e9ead63209af5f7bee93892fb",
        "260a0bfcadb7cabd2f27ff349be508aa940e901ddc6e71f491181911260f79c5",
        "56be896de022d2728f47ac843407c00fdf2f868b75e8419d51b0634a3d47678b",
        "8c4d466f7f0f1c59a39a7b9af87aa081187510612a417b927bb20489a17baa74",
        "bf0e054d12c423a10557591d79a8c7ec697d9bf58ae8684143898a7e9bcbd7fa",
        "307d220627391c4e66bda4e336a5a6637636bd21c947dcd71753434eeaa9f452",
        "79c6f4b7f58662408a407f0f0bccee80526a28ebc9c40c3ae407d32dcf313479",
        "3e4cf5df32f61d4bb0b1943dc61adbeee9e8615dbb21de7122b9ff4405a779c6",
        "d7402feddeacbfa61ef6a7bfdd5a676d26214c4433cc41e3306c43ea78b95765",
        "6c0981a5f3717ee5b7d583fe62840e549a9b432b26fbfb27c024b0ab5ef68721",
        "3d1c36c13e3e0880ce7ca28f93b8a3fa37655b625ec1131c05ec0ee4218003cd",
        "a3d0e6f9780af3467d1dc8807f56966c555770bdcde43c2fa8f76a0e94b94cb4",
        "e27c6f436a1ad4b24b6710bda71cbc1d2f0bbfa464979c8623cf62fab3389456",
        "088ec846e5ab77d2e03aaa48ed3990ca15c519e26bb15b0debaf5072797b26f0",
        "e6cb244fedec5a55f4ccf11c15a12f5f9e82f8618b5d405d9089631f2c988cca",
        "d7ff23fb624f7a5ff898ba20783d2fb6102ce4219ea1158b0f36236ee4f4dae3",
        "267e0586d3e240937ba2e326904062fee4c940934af22cecb5e6901479315fe3",
        "9e59685b3e3b5c24244997795f34ea988856cbcca4158f16f28a36c2cfcd0c83",
        "b6319fc777523fa930123cc9ecc7eeae180917df08eca7cd57673e9ab8b9bd48",
        "05124bb292c76225906bf4d3d77ea97f2b76d2bdac0a79c69940afb18c789ed2",
        "9433260807b273438f62c83e69b7732262bd1813d3f781c333d86e17c5cc8ee6",
        "548ba5ca0d53a8e65bdd84933a23c2ad89e5e03f299781e509ec2db461ba1034",
        "8ee69cc8c83cbeb7f48d5eb61a50a15d514b9a147a3f426eb6504c7970fad0ca",
        "be3e104375e119799e0e131d7687ab4df9515131509cb99d7bc290b4d59f4af5",
        "c42f1ed7c9fb408f36556d065a8d185f4c9349501599d6649d87d0621c98a5a1",
        "52606e121483e05a49d930f39464da9080fe55712265f01b349082a22e204134",
        "e82dbb51520aef1b51a84a78c9e4c73ab4d3baa29958c685554495c41c051b75",
        "81fbe50cce17f8b7979e938bb053693942b4a78bc6a8404e980465cd0d2eb465",
        "98376e74beaabb85a8dbf6a68e039646fa340ad019a893f4d05f3c28d61858cf",
        "0ea6799a7e5b17e554ad5a764422fa7db68c0ccaf994392168e116f3cad02278",
        "a290f19fd63f077d53c249197269ae8c9193d996ada37cd62b40f4c733ba8b99",
        "212408fb2aa54ae13c3723a30f1fc11ec1ca202a61aff1e4a203c038cda20c12",
        "918eb5874e1a16367cbf1ecfd54d82ade71424a0ea5f7d5d7cde156781315a59",
        "ddddee6072b44571e272b5e62f9d148c238693ac9712bc58da41a9bc28b221f1",
        "21ea1f8ecf6d7469bd10decc2bb9134868d5fe6450df84be609b64002de61fe7",
        "da9cf8931cd4d791a44668d5623fc8e60ff4a80029ef8f19b6265ba90a1e6226",
        "247444cc60f31d2a168175f3aa992393d23d73bc6ad4156c826f8f67d0c7ef8c",
        "f83fe952886e180bb74e5aeb7acd6e86a8e4a86d65eb99a5100491a2f03d467f",
        "cfd6d93323d527701614c5bc5d997ea5fd6de1327a06f1537668104db53b998c",
        "cf6093ef05eb5408039f681a72381d39c903534f197cc9df112410dc2a33ebd6",
        "4b4efb4376727d03d91a26d88c45cc4829aa41dc8e6b5c04f825aa34ba8533d3",
        "d4bc5cb6d86efcf407ea8c6160f6524d11befb0c49f8c9b97607f32149f3d068",
        "29b93e7441520e218d5d02e775a7fa0a62558e9fee3557f18b60ed4706f31390",
        "c543ae9879ca0927ea8e7c98902798e9de628ff8087b380e7b0b01c72f823923",
        "68621eadac0e8488478bac82bfcda78447c477ba9a5401d1bfc7a7156906f8f7",
        "b44ac4cc42b6b7283804912fbc72040e7b646330b1728d950126928a9596ed43",
        "f4def7623c7c8c79b36e7c7d33add721336e44e7f38ad3eb3e08753839e65ad4",
        "1f49b01e79ad86a66e45d77a27d735f66788ea56b7867f16a9379b7063fd548a",
        "3fcc868b939eab24e818e145d9b2a592f7ec021209af6c7c0649ed6fe78b8903",
        "ba0c80fcdf1b3e1d7aea08c5b2b32bd8a4b42d2be7c7ab624842c71d988a7791",
        "21f0b9e2918df2908456a5e100b51720eb630a9b9619f556019565eca3100502",
        "e52daa467a8384e1fac25243b27722ce3d802b325bdb59cb959e388560bc0d5b",
        "705bd69ccd5a7db695a9bb17a1b610e53e383436774769775e626ccd9caacae1",
        "97814f7614ca66e8e3d844c391391d2ba049a84d61456abf6bdfcc1a5eabf07c",
        "2eb1e5effc7e44ee216039c73966866954e01b2d86b713f65404664eecafd1a5",
        "06dc0a0eb067d30460df5ff8096ab13b60ce2ab2963276ee64d9605e05cdd78b",
        "2e50ccdc797e47e979591e062450c83d3c7ff70710c839c6b41b7f6cc6eb3ccf",
        "6abe8c25d917d241288ae8f85039db1971380a4b6a1911c3db5d0ea505ec7348",
        "8d795507659bdd58dadc2129bc895cc76bc365898f7a8d90aff4c40f62299b7c",
        "c407df765c9847e1f01da2b40c74ecf754a85ec118b85553ecacc43c37b8aa83",
        "43f987152623c4b942c79492a7f4ddcb2b9b016b039251b1db8540818dffb9d7",
        "9f6acfb1aa214e8ac17f96f3a60531747a609d04a35d944cfa725eaf231c321a",
        "a9f7371a481d33a57f7c498446e64e0c75ae0f28df81e876b2f9c6823a7f2e4d",
        "94c87e6b6b9c2489e377580515e515a8b974b0a4a0c0daebea409b120a398fdc",
        "874ababcaeb79d7dbb4fb7f5787270df25246c7a0b602bfdbb36479bbf6517d2",
        "25164011b0b5477527268e66e4868d4b506bff332fbf3d9c7e67b5be49585d97",
        "15a334b7251bed434f95e12ff55c486b3b2227c510e43950692ea2c0fefb5cee",
        "36ec4082523f51c047fb10c1104098b7b9d48fec9cfba55b10b58bb6090e25b7",
        "1d0dfef248d482baa5418ce989c3c7b9021dfcabdc909762c67cba9e7a96ae88",
        "e763dce4680dfbbe8ff6081ffd87167bdf22415c14c2887967befd7afa3df0b7",
        "6d1839f97acd392846610a9c6697bde6a4ad1da120ecdf588db05fd9cad08d55"
    ],
    "time": 1368328721,
    "mediantime": 1368327088,
    "nonce": 2315762778,
    "bits": "1a01aa3d",
    "difficulty": 10076292.88341872,
    "chainwork": "000000000000000000000000000000000000000000000040574d4344c56cd4a0",
    "nTx": 124,
    "previousblockhash": "000000000000015f416afc2a44461adb178764a4fb45e5935c0a5717edf451a8",
    "nextblockhash": "00000000000000aada29fb28a9dcb6891f7b5254ba77393c6e3a436d6e4f0090"
}


# rpc_getrawtransaction("05f1f0c7fc25005e7c6e56805130b4d540125a8d09f81ec3da621f99ee5d15c1")
coinbase_tx_vector = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503ef98030400001059124d696e656420627920425443204775696c640800000037000011caffffffff01a0635c95000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000"


################################################################################
# Unit Tests
################################################################################


class TestConversions(unittest.TestCase):
    def test_int2lehex(self):
        self.assertEqual(ntgbtminer.int2lehex(0x1a, 1), "1a")
        self.assertEqual(ntgbtminer.int2lehex(0x1a2b, 2), "2b1a")
        self.assertEqual(ntgbtminer.int2lehex(0x1a2b3c4d, 4), "4d3c2b1a")
        self.assertEqual(ntgbtminer.int2lehex(0x1a2b3c4d5e6f7a8b, 8), "8b7a6f5e4d3c2b1a")

    def test_int2varinthex(self):
        self.assertEqual(ntgbtminer.int2varinthex(0x1a), "1a")
        self.assertEqual(ntgbtminer.int2varinthex(0x1a2b), "fd2b1a")
        self.assertEqual(ntgbtminer.int2varinthex(0x1a2b3c), "fe3c2b1a00")
        self.assertEqual(ntgbtminer.int2varinthex(0x1a2b3c4d), "fe4d3c2b1a")
        self.assertEqual(ntgbtminer.int2varinthex(0x1a2b3c4d5e), "ff5e4d3c2b1a000000")

    def test_bitcoinaddress2hash160(self):
        self.assertEqual(ntgbtminer.bitcoinaddress2hash160("14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"), "27a1f12771de5cc3b73941664b2537c15316be43")


class TestTransaction(unittest.TestCase):
    def test_encode_coinbase_height(self):
        self.assertEqual(ntgbtminer.tx_encode_coinbase_height(235759), "03ef9803")

    def test_make_coinbase(self):
        coinbase_script = "0400001059124d696e656420627920425443204775696c640800000037000011ca"
        address = "14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"
        value = 2505860000
        height = 235759

        self.assertEqual(ntgbtminer.tx_make_coinbase(coinbase_script, address, value, height), coinbase_tx_vector)

    def test_compute_hash(self):
        self.assertEqual(ntgbtminer.tx_compute_hash(coinbase_tx_vector), "05f1f0c7fc25005e7c6e56805130b4d540125a8d09f81ec3da621f99ee5d15c1")

    def test_compute_merkle_root(self):
        self.assertEqual(ntgbtminer.tx_compute_merkle_root(block_vector['tx']), block_vector['merkleroot'])


class TestBlock(unittest.TestCase):
    def test_bits2target(self):
        self.assertEqual(ntgbtminer.block_bits2target("1a01aa3d").hex(), "00000000000001aa3d0000000000000000000000000000000000000000000000")
        self.assertEqual(ntgbtminer.block_bits2target("1b0404cb").hex(), "00000000000404cb000000000000000000000000000000000000000000000000")

    def test_block_hash(self):
        # Copy time key to curtime key to make block vector look like block template
        block_vector['curtime'] = block_vector['time']

        # Form block header and hash
        header = ntgbtminer.block_make_header(block_vector)
        header_hash = ntgbtminer.block_compute_raw_hash(header)

        # Verify block hash
        self.assertEqual(header_hash.hex(), block_vector['hash'])

        # Check block hash meets or fails various targets
        target_hash = ntgbtminer.block_bits2target(block_vector['bits'])
        self.assertEqual(header_hash < target_hash, True)
        header_hash = b'\x01' + header_hash[1:]
        self.assertEqual(header_hash < target_hash, False)
        header_hash = b'\x00' * 6 + b'\x02' + header_hash[8:]
        self.assertEqual(header_hash < target_hash, False)
        header_hash = b'\x00' * 6 + b'\x01' + header_hash[8:]
        self.assertEqual(header_hash < target_hash, True)
        header_hash = b'\x00' * 6 + b'\x01\xaa\x3c' + header_hash[10:]
        self.assertEqual(header_hash < target_hash, True)
        header_hash = b'\x00' * 6 + b'\x01\xaa\x3d' + header_hash[10:]
        self.assertEqual(header_hash < target_hash, False)

    def test_block_mine(self):
        def reset_block_vector():
            # Manipulate the transactions in real block to look like a block template
            block_vector['transactions'] = []
            for i in range(1, len(block_vector['tx'])):
                tx = {'hash': block_vector['tx'][i], 'data': 'abc'}
                block_vector['transactions'].append(tx)

            # Copy time key to curtime key to make block look like block template
            block_vector['curtime'] = block_vector['time']

            # Clear block hash
            block_vector['hash'] = ""

        # Setup generation transaction parameters with same extra nonce start as the mined black
        coinbase_message = "0400001059124d696e656420627920425443204775696c640800000037"
        extra_nonce_start = 0xca110000
        address = "14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"
        block_vector['coinbasevalue'] = 2505860000

        # Test timeout with different extra_nonce_start
        reset_block_vector()
        mined_block, hash_rate = ntgbtminer.block_mine(block_vector, coinbase_message, 0, address, timeout=1, debugnonce_start=2315460000)
        self.assertEqual(mined_block, None)

        # Test success
        reset_block_vector()
        mined_block, hash_rate = ntgbtminer.block_mine(block_vector, coinbase_message, extra_nonce_start, address, timeout=60, debugnonce_start=2315460000)
        self.assertEqual(mined_block['hash'], "000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7")


if __name__ == "__main__":
    unittest.main()
