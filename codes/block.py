#import blkUtils
import hashlib, json, sys
import pickle
import txnUtils

def hashMe(msg=""):
    # For convenience, this is a helper function that wraps our hashing algorithm
    if type(msg)!=str:
        msg = json.dumps(msg,sort_keys=True)  # If we don't sort keys, we can't guarantee repeatability!
        
    if sys.version_info.major == 2:
        return unicode(hashlib.sha256(msg).hexdigest(),'utf-8')
    else:
        return hashlib.sha256(str(msg).encode('utf-8')).hexdigest()


state = {}  # Define the initial state
genesisBlockTxns = [state]
genesisBlockContents = {u'blockNumber':0, u'parentHash':None, u'txnCount':1, u'txns':genesisBlockTxns}
genesisHash = hashMe(genesisBlockContents )
genesisBlock = {u'hash':genesisHash, u'contents':genesisBlockContents}
genesisBlockStr = json.dumps(genesisBlock, sort_keys=True)

chain = [genesisBlock]

print "chain[0] \n", chain[0]

def makeBlock(txns,chain):
    parentBlock = chain[-1]
    parentHash  = parentBlock[u'hash']
    blockNumber = parentBlock[u'contents'][u'blockNumber'] + 1
    txnCount    = len(txns)
    blockContents = {u'blockNumber':blockNumber,u'parentHash':parentHash,
                     u'txnCount':len(txns),'txns':txns}
    blockHash = hashMe( blockContents )
    block = {u'hash':blockHash,u'contents':blockContents}
    
    return block


blockSizeLimit = 5  # Arbitrary number of transactions per block- 
               #  this is chosen by the block miner, and can vary between blocks!


with open ('txnBuffer.txt', 'rb') as fp:
    txnBuffer = pickle.load(fp)
print "length:", len(txnBuffer)
print "txnBuffer:", txnBuffer

while len(txnBuffer) > 0:
    bufferStartSize = len(txnBuffer)  
    ## Gather a set of valid transactions for inclusion
    txnList = []
    while (len(txnBuffer) > 0) & (len(txnList) < blockSizeLimit):
        newTxn = txnBuffer.pop()
	validTxn = txnUtils.verifyTxnSignature(newTxn)
        #validTxn = isValidTxn(newTxn,state) # This will return False if txn is invalid
        if validTxn:           # If we got a valid state, not 'False'
            txnList.append(newTxn)
            #state = updateState(newTxn,state)
        else:
            print("ignored transaction")
            sys.stdout.flush()
            continue  # This was an invalid transaction; ignore it and move on
    ## Make a block
    myBlock = makeBlock(txnList,chain)
    chain.append(myBlock)

print "chain", chain[0], chain[1]
