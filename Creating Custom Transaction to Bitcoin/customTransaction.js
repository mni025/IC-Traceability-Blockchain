// Create a new directory, install bitcore-explorers, and run the node shell
mkdir bitcoin && cd bitcoin
npm install --save bitcore-explorers
node

// Require the Bitcore libraries into the global namespace
var bitcore = require(“bitcore-lib”)
var explo = require(“bitcore-explorers”)
var shell = {}

// Generate a new Bitcoin address
var slug = “myNameIsNazmul”
var hash = bitcore.crypto.Hash.sha256(new Buffer(slug))
var bn = bitcore.crypto.BN.fromBuffer(hash)
var pKey = bitcore.PrivateKey(bn)
var addr = pKey.toAddress()

// Link to how Bitcoin addresses are created
"https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address"

// Connect your local shell with a remote BitPay node
var insight = new explo.Insight()

// Get Info about an address
insight.address(addr, (error, result) => { shell.addr = result })
insight.getUnspentUtxos(addr, (error, result) => { shell.utxos = result })

// Create a Bitcoin transaction
var tx = bitcore.Transaction()
tx.from(utxoObject) // As many times as needed
tx.fee(feeAmount) // In Satoshis
tx.to(addr2, amount) // In Satoshis
tx.change(addr) // Send remaining balance back to this account
tx.addData() // Add metadata to the transaction
tx.sign(privateKey)
tx.serialize() // Check for errors

// Send the Bitcoin transaction to the live network
insight.broadcast(tx, (error, txId) => { shell.error = error; shell.txId = txId })
