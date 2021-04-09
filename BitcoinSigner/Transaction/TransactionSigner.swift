//
//  TransactionSigner.swift
//  BitcoinSigner
//
//  Created by 翟泉 on 2020/8/27.
//  Copyright © 2020 cezres. All rights reserved.
//

import Foundation

class TransactionSigner {
}

extension TransactionSigner {
    struct InputSignature {
        let script: Data
        let witness: [Data]
    }

    static func witnessSignatureP2SH_P2WPKH(rawTransaction: Data, inputValues: [UInt64], privateKey: PrivateKey) throws -> Data {
        let transaction = Transaction.deserialize(rawTransaction)
        let sigHashes = TxSigHashes(tx: transaction)
        let witnessProgram = try Script().append(.OP_0).appendData(privateKey.publicKey().pubkeyHash).data

        var signatures = [InputSignature]()
        for index in 0..<transaction.inputs.count {
            let signatureScript = try Script().appendData(witnessProgram).data

            let signatureHash = try calcWitnessSignatureHash(script: privateKey.publicKey().pubkeyHash, sigHashes: sigHashes, tx: transaction, idx: index, amount: inputValues[index], isWitnessPubKeyHash: true)
            var signature = privateKey.sign(signatureHash)
            signature += UInt8(0x1) // SigHashType -- SigHashAll = 0x1
            let witness = [signature, privateKey.publicKey().data]

            signatures.append(.init(script: signatureScript, witness: witness))
        }

        return serializeTx(transaction, signatures: signatures)
    }

    static func witnessSignatureP2SH_P2WSH(rawTransaction: Data, inputValues: [UInt64], extendedPublicKeys: [String], signaturesRequired: UInt, privateKey: PrivateKey) throws -> [[String]] {
        let transaction = Transaction.deserialize(rawTransaction)
        let sigHashes = TxSigHashes(tx: transaction)
        let publicKeys = extendedPublicKeys.compactMap { PublicKey(extended: $0, network: .mainnetBTC) }
        let redeemScript = Script(publicKeys: publicKeys, signaturesRequired: signaturesRequired)!

        var signatures = [[String]]()
        for index in 0..<transaction.inputs.count {
            let signatureHash = try calcWitnessSignatureHash(script: redeemScript.data, sigHashes: sigHashes, tx: transaction, idx: index, amount: inputValues[index], isWitnessPubKeyHash: false)
            var signature = privateKey.sign(signatureHash)
            signature += UInt8(0x1) // SigHashType -- SigHashAll = 0x1
            signatures.append([signature.hex])
        }

        return signatures
    }

    static func serializeTx(_ tx: Transaction, signatures: [InputSignature]) -> Data {
        var data = Data()

        data += UInt32(tx.version)
        data += [UInt8(0x00), UInt8(0x01)] // witessMarkerBytes

        // writeTxIn
        data.writeVarInt(UInt64(tx.inputs.count))
        for (i, input) in tx.inputs.enumerated() {
            data += input.previousOutput.hash
            data += UInt32(input.previousOutput.index)
            data.writeVarBytes(signatures[i].script)
            data += UInt32(input.sequence)
        }

        // writeTxOut
        data.writeVarInt(UInt64(tx.outputs.count))
        for output in tx.outputs {
            data += UInt64(output.value)
            data.writeVarBytes(output.lockingScript)
        }

        // writeTxWitness
        for (i, _) in tx.inputs.enumerated() {
            let witness = signatures[i].witness
            data.writeVarInt(UInt64(witness.count))
            for item in witness {
                data.writeVarBytes(item)
            }
        }

        data += UInt32(tx.lockTime)
        return data
    }

    static func calcWitnessSignatureHash(script: Data, sigHashes: TxSigHashes, tx: Transaction, idx: Int, amount: UInt64, isWitnessPubKeyHash: Bool) throws -> Data {
        if idx >= tx.inputs.count {
            throw NSError(domain: "idx \(idx) but \(tx.inputs.count) txins", code: -1, userInfo: nil)
        }

        var sigHash = Data()

        sigHash += UInt32(tx.version)

        sigHash += sigHashes.hashPrevOuts
        sigHash += sigHashes.hashSequence

        let input = tx.inputs[idx]
        sigHash += input.previousOutput.hash
        sigHash += UInt32(input.previousOutput.index)

        if isWitnessPubKeyHash {
            sigHash += UInt8(0x19)
            sigHash += OpCode.OP_DUP.value
            sigHash += OpCode.OP_HASH160.value
            sigHash += UInt8(0x14) // OP_DATA_20
            sigHash += script
            sigHash += OpCode.OP_EQUALVERIFY.value
            sigHash += OpCode.OP_CHECKSIG.value
        } else {
            sigHash.writeVarBytes(script)
        }

        sigHash += UInt64(amount)
        sigHash += UInt32(input.sequence)

        sigHash += sigHashes.hashOutputs

        sigHash += UInt32(tx.lockTime)
        sigHash += UInt32(1) // sign type

        let signatureHash = Crypto.sha256sha256(sigHash)
        return signatureHash
    }
}

struct TxSigHashes: CustomStringConvertible {
    var hashPrevOuts: Data
    var hashSequence: Data
    var hashOutputs: Data

    init(tx: Transaction) {
        hashPrevOuts = calcHashPrevOuts(tx)
        hashSequence = calcHashSequence(tx)
        hashOutputs = calcHashOutputs(tx)
    }

    var description: String {
        """
        hashPrevOuts: \(hashPrevOuts.hex)
        hashSequence: \(hashSequence.hex)
        hashOutputs: \(hashOutputs.hex)
        """
    }
}

func calcHashPrevOuts(_ tx: Transaction) -> Data {
    var data = Data()
    for input in tx.inputs {
        data += input.previousOutput.hash
        data += input.previousOutput.index
    }
    return Crypto.sha256sha256(data)
}

func calcHashSequence(_ tx: Transaction) -> Data {
    var data = Data()
    for input in tx.inputs {
        data += input.sequence
    }
    return Crypto.sha256sha256(data)
}

func calcHashOutputs(_ tx: Transaction) -> Data {
    var data = Data()
    for output in tx.outputs {
        data += UInt64(output.value)
        data.writeVarBytes(output.lockingScript)
    }
    return Crypto.sha256sha256(data)
}

extension Data {
    mutating func writeVarInt(_ value: UInt64) {
        if value < 0xfd {
            self += UInt8(value)
        } else if value <= UInt16.max {
            self += UInt8(0xfd)
            self += UInt16(value)
        } else if value <= UInt32.max {
            self += UInt8(0xfe)
            self += UInt32(value)
        } else {
            self += UInt8(0xff)
            self += UInt64(value)
        }
    }

    mutating func writeVarBytes(_ data: Data) {
        writeVarInt(UInt64(data.count))
        self += data
    }
}
