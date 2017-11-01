# https://pypi.python.org/pypi/ecdsa/0.10

import ecdsa
import hashlib
import struct
import unittest
import utils
import keyUtils

#############################################################################################
#create signed transaction
#############################################################################################
def makeSignedTransaction(privateKey, outputTransactionHash, sourceIndex, scriptPubKey, outputs):
    myTxn_forSig = (makeRawTransaction(outputTransactionHash, sourceIndex, scriptPubKey, outputs)
         + "01000000") # hash code
    print"myTxn_forSig: \n" + myTxn_forSig + '\n'
    s256 = hashlib.sha256(hashlib.sha256(myTxn_forSig.decode('hex')).digest()).digest()

    #print "s256: \n" + s256 + '\n'
    sk = ecdsa.SigningKey.from_string(privateKey.decode('hex'), curve=ecdsa.SECP256k1)
    #print "sk: \n" + sk + '\n'
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + '\01' # 01 is hashtype
    #print "sig: \n" + sig + '\n'
    pubKey = keyUtils.privateKeyToPublicKey(privateKey)
    #print "pubKey: \n" + pubKey + '\n'
    scriptSig = utils.varstr(sig).encode('hex') + utils.varstr(pubKey.decode('hex')).encode('hex')
    #print "scriptSig: \n" + scriptSig + '\n'
    signed_txn = makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
    print "signed_txn: \n" + signed_txn + '\n'
    verifyTxnSignature(signed_txn)
    return signed_txn

# Makes a transaction from the inputs
# outputs is a list of [redemptionSatoshis, outputScript]
def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        return (struct.pack("<Q", redemptionSatoshis).encode('hex') +
        '%02x' % len(outputScript.decode('hex')) + outputScript)
    formattedOutputs = ''.join(map(makeOutput, outputs))
    return (
        "01000000" + # 4 bytes version
        "01" + # varint for number of inputs
        outputTransactionHash.decode('hex')[::-1].encode('hex') + # reverse outputTransactionHash
        struct.pack('<L', sourceIndex).encode('hex') +
        '%02x' % len(scriptSig.decode('hex')) + scriptSig +
        "ffffffff" + # sequence
        "%02x" % len(outputs) + # number of outputs
        formattedOutputs +
        "00000000" # lockTime
        )
#############################################################################################
        


#############################################################################################
#transaction verification
#############################################################################################
# Verifies that a transaction is properly signed, assuming the generated scriptPubKey matches
# the one in the previous transaction's output
def verifyTxnSignature(txn):                    
    parsed = parseTxn(txn)      
    signableTxn = getSignableTxn(parsed)
    hashToSign = hashlib.sha256(hashlib.sha256(signableTxn.decode('hex')).digest()).digest().encode('hex')
    assert(parsed[1][-2:] == '01') # hashtype
    sig = keyUtils.derSigToHexSig(parsed[1][:-2])
    public_key = parsed[2]
    vk = ecdsa.VerifyingKey.from_string(public_key[2:].decode('hex'), curve=ecdsa.SECP256k1)
    assert(vk.verify_digest(sig.decode('hex'), hashToSign.decode('hex')))
    print "transaction verified"
    fo = open("ledger.txt","wb")
    fo.write("new transaction added: \n" + txn)

# Returns [first, sig, pub, rest]
def parseTxn(txn):
    first = txn[0:41*2]
    scriptLen = int(txn[41*2:42*2], 16)
    script = txn[42*2:42*2+2*scriptLen]
    sigLen = int(script[0:2], 16)
    sig = script[2:2+sigLen*2]
    pubLen = int(script[2+sigLen*2:2+sigLen*2+2], 16)
    pub = script[2+sigLen*2+2:]
            
    assert(len(pub) == pubLen*2)
    rest = txn[42*2+2*scriptLen:]
    return [first, sig, pub, rest] 

# Substitutes the scriptPubKey into the transaction, appends SIGN_ALL to make the version
# of the transaction that can be signed
def getSignableTxn(parsed):
    first, sig, pub, rest = parsed
    inputAddr = utils.base58CheckDecode(keyUtils.pubKeyToAddr(pub))
    return first + "1976a914" + inputAddr.encode('hex') + "88ac" + rest + "01000000"
#############################################################################################




#############################################################################################
#transaction output
#############################################################################################
#shows the details of transaction
def showTxn(txn):
    version = txn[0:4*2]
    #print "version: \n" + version
    txn_in_count = txn[4*2:5*2]
    #print "txn_in_count: \n" + txn_in_count
    prev_txn_hash = txn[5*2:37*2]
    print "prev_txn_hash: \n" + prev_txn_hash
    prev_txn_index = txn[37*2:41*2]
    #print "prev_txn_index: \n" + prev_txn_index
    scriptLen = int(txn[41*2:42*2], 16)
    #print scriptLen
    #print "scriptLen: \n" + scriptLen
    script = txn[42*2:42*2+2*scriptLen]
    print "sig_script: \n" + script
    #sigLen = int(script[0:2], 16)
    #sig = script[2:2+sigLen*2]
    #pubLen = int(script[2+sigLen*2:2+sigLen*2+2], 16)
    #pub = script[2+sigLen*2+2:]
    pos = 42*2+2*scriptLen
    sequence = "ffffffff"
    #print "sequence: \n" + sequence
    txn_out_count = txn[pos+8:pos+10]
    #print "txn_out_count: \n" + txn_out_count
    value = txn[pos+10:pos+26]
    print "value: \n" +  value
    pk_script_len = int(txn[pos+26:pos+28], 16)
    pk_script = txn[pos+28:pos+28+pk_script_len*2]
    #print version + '\n' + txn_in_count + '\n' + prev_txn_hash + '\n' + prev_txn_index + '\n'
    #print script
    #print sequence + '\n' + txn_out_count + '\n' +  value + '\n'
    #print pk_script_len 
    print "pk_script: \n" + pk_script 
#############################################################################################


#############################################################################################    
class TestTxnUtils(unittest.TestCase):
    def test_verifyParseTxn(self):
        txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
                        "8a47" +
                        "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
                        "41" +
                        "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
                        "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
                        "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")


        parsed = parseTxn(txn)
        self.assertEqual(parsed[0], "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000")
        self.assertEqual(parsed[1], "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01")
        self.assertEqual(parsed[2], "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55")
        self.assertEqual(parsed[3], "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
                        "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")

    def test_verifySignableTxn(self):
        txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
                        "8a47" +
                        "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
                        "41" +
                        "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
                        "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
                        "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")

        parsed = parseTxn(txn)      
        myTxn_forSig = ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
                        "1976a914" + "167c74f7491fe552ce9e1912810a984355b8ee07" + "88ac" +
                        "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
                        "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000" +
                        "01000000")
        signableTxn = getSignableTxn(parsed)
        self.assertEqual(signableTxn, myTxn_forSig)

    def test_verifyTxn(self):
        txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
                        "8a47" +
                        "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
                        "41" +
                        "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
                        "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
                        "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")

        verifyTxnSignature(txn)

    def test_makeRawTransaction(self):
        txn = makeRawTransaction(
            "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", # output transaction hash
            1, # sourceIndex
            "76a914010966776006953d5567439e5e39f86a0d273bee88ac", # scriptSig
            [[99900000, 
            "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac"]], # outputScript
            ) + "01000000" # hash code type
        self.assertEqual(txn,
            "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
            "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
            "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
            "0000000001000000")
   
    def test_makeSignedTransaction(self):
        privateKey = keyUtils.wifToPrivateKey("5KawhzxJoVhw1hw75WTtXPUtsLVXFHLYZXDAWGRQxo597X4EwFX")

        signed_txn = makeSignedTransaction(privateKey,
            "c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9", # output (prev) transaction hash
            0,
            keyUtils.addrHashToScriptPubKey("167WXe5yJXqsX8bcmPUMR3CzMib89NU3da"), #input address
            [[00001,
            keyUtils.addrHashToScriptPubKey("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")] #output address
#,           [20000,            
#           keyUtils.addrHashToScriptPubKey("15nhZbXnLMknZACbb3Jrf1wPCD9DWAcqd7")]
            ]
            )
        showTxn(signed_txn)
        #verifyTxnSignature(signed_txn)
#############################################################################################
if __name__ == '__main__':
    unittest.main()
