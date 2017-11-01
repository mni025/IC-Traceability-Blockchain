import keyUtils
import utils
import hashlib
import txnUtils
import pickle

txnBuffer = []

#User frist provides the WIF private key which is converted to the private key 
wifPrivateKey = raw_input('Enter your wif private key: ') #5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu
print "Received wif private key is:", wifPrivateKey
privateKey = keyUtils.wifToPrivateKey(wifPrivateKey)
print "Private key is :", privateKey                      #E97174E793C7524C0A68EDA86458682BD9C5510E6E3614CC5CECDFFE966C925B

#user provides the previous transaction hash              #c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9
outputTransactionHash = raw_input('Enter previous transaction hash: ')
print "Received previous transaction hash is: ", outputTransactionHash

#user provides recipient's address                        #1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa
addrHash = raw_input('Enter recepient address: ')
print "Received recipient address:", addrHash
print "length:", len(addrHash)

#public key is generated from the private key using Ellicptic Curve Cryptography (ECC) 
#392B964E911955ED50E4E368A9476BC3F9DCC134280E15636430EB91145DAB739F0D68B82CF33003379D885A0B212AC95E9CDDFD2D391807934D25995468BC55
pubKey = keyUtils.privateKeyToPublicKey(privateKey)
print "Sender's Public Key: ", pubKey

#public keys is hashed
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(hashlib.sha256(pubKey.decode('hex')).digest())
digest = (ripemd160.digest()).encode('hex')
print "Digest:", digest                                   #167c74f7491fe552ce9e1912810a984355b8ee07

#scriptPubKey from hash public key
scriptPubKey = '76a914' + digest + '88ac'

#public key is hashed and then base58 encoded
publKeyToAddress = utils.base58CheckEncode(0,digest.decode('hex'))
pubKeyToAddress = keyUtils.pubKeyToAddr(pubKey)
print "publKeyToAddress: ", publKeyToAddress              #133txdxQmwECTmXqAr9RWNHnzQ175jGb7e
print "pubKeyToAddress:  ", pubKeyToAddress               #133txdxQmwECTmXqAr9RWNHnzQ175jGb7e

signed_txn = txnUtils.makeSignedTransaction(privateKey,outputTransactionHash,0,scriptPubKey,
                                   [[00001,keyUtils.addrHashToScriptPubKey(addrHash)]])


txnBuffer.append(signed_txn)
#fo = open("txnBuffer.txt","wb")
#for item in txnBuffer:
#  fo.write("%s\n" % item)

#itemlist = ['a','b','c']

with open('txnBuffer.txt', 'wb') as fp:
    pickle.dump(txnBuffer, fp)
