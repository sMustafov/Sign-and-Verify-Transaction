const CryptoJS = require("crypto-js");
const EC = require('elliptic').ec;
const secp256k1 = new EC('secp256k1');

function signData(data, privKey) {
    let keyPair = secp256k1.keyFromPrivate(privKey);
    let signature = keyPair.sign(data);
   // console.log("[" + signature.r.toString(16) + ", " + signature.s.toString(16) + "]");
    return [signature.r.toString(16), signature.s.toString(16)];
}

function decompressPublicKey(pubKeyCompressed) {
    let pubKeyX = pubKeyCompressed.substring(0, 64);
    let pubKeyYOdd = parseInt(pubKeyCompressed.substring(64));
    let pubKeyPoint = secp256k1.curve.pointFromX(pubKeyX, pubKeyYOdd);
    return pubKeyPoint;
}

function verifySignature(data, publicKey, signature) {
    let pubKeyPoint = decompressPublicKey(publicKey);
    let keyPair = secp256k1.keyPair({pub: pubKeyPoint});
    let valid = keyPair.verify(data, {r: signature[0], s: signature[1]});
    console.log(valid);
    return valid;
}

class Transaction {
    constructor(from, to, value, fee, dateCreated, senderPubKey, transactionDataHash, senderSignature, minedInBlockIndex, transferSuccessful)  {
        this.from = from; // Sender address: 40 hex digits
        this.to = to; // Recipient address: 40 hex digits
        this.value = value; // Transfer value: integer
        this.fee = fee; // Mining fee: integer
        this.dateCreated = dateCreated;   // ISO-8601 string
        this.senderPubKey = senderPubKey; // 65 hex digits
        this.transactionDataHash = transactionDataHash; // 64 hex digits

        // Calculate the transaction data hash if it is missing
        if (this.transactionDataHash === undefined)
            this.calculateDataHash();

        this.senderSignature = senderSignature; // hex_number[2][64]
        this.minedInBlockIndex = minedInBlockIndex; // integer
        this.transferSuccessful = transferSuccessful; // bool
    }

    calculateDataHash() {
        let tranData = {
            'from': this.from,
            'to': this.to,
            'senderPubKey': this.senderPubKey,
            'value': this.value,
            'fee': this.fee,
            'dateCreated': this.dateCreated
        };

        let tranDataJSON = JSON.stringify(tranData);
        this.transactionDataHash = CryptoJS.SHA256(tranDataJSON).toString();

        console.log(tranDataJSON);
    }

    sign(privateKey) {
        this.senderSignature = signData(this.transactionDataHash, privateKey);
    }

    verifySignature() {
        return verifySignature(this.transactionDataHash, this.senderPubKey, this.senderSignature);
    }
}

transaction = new Transaction(
    "c3293572dbe6ebc60de4a20ed0e21446cae66b17",
    "f51362b7351ef62253a227a77751ad9b2302f911",
    25000,
    10,
    "2018-02-10T17:53:48.972Z",
    "c74a8458cd7a7e48f4b7ae6f4ae9f56c5c88c0f03e7c59cb4132b9d9d1600bba1",
    "f241a5598fbe5ba048918fa1cafe8eb727794cfb0f72f425ba332479de22e2b7",
    ["1aaf55dcb11060749b391d547f37b4727222dcb90e793d9bdb945c64fe4968b0", "87250a2841f7a56910b0f7ebdd067589632ccf19d352c15f16cfdba9b7687960"],
    0,
    true
);


transaction.calculateDataHash();
console.log();

transaction.sign("7e4670ae70c98d24f3662c172dc510a085578b9ccc717e6c2f4e547edd960a34");
console.log();

transaction.verifySignature();