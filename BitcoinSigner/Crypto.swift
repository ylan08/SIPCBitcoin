//
//  Crypto.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation
import CryptoSwift
import ripemd160
import secp256k1

struct Crypto {
    public static func sha1(_ data: Data) -> Data {
        return data.sha1()
    }

    public static func sha256(_ data: Data) -> Data {
        return data.sha256()
    }

    public static func sha256sha256(_ data: Data) -> Data {
        return sha256(sha256(data))
    }

    public static func ripemd160(_ data: Data) -> Data {
        return data.ripemd160
    }

    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(sha256(data))
    }

    public static func hmacsha512(data: Data, key: Data) -> Data {
        do {
            let bytes = try HMAC(key: key.bytes, variant: .sha512).authenticate(data.bytes)
            return Data(bytes)
        } catch {
            return Data()
        }
    }

    public static func sign(_ data: Data, privateKey: PrivateKey) throws -> Data {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else { throw BitcoinSigner.Error.signError }
        var signature = secp256k1_ecdsa_signature()
        var normalizedSignature = secp256k1_ecdsa_signature()
        secp256k1_ecdsa_sign(ctx, &signature, data.bytes, privateKey.data.bytes, nil, nil)
        secp256k1_ecdsa_signature_normalize(ctx, &normalizedSignature, &signature)
        var siglen: size_t = 74
        var der = Data(repeating: 0x00, count: siglen)
        let result = der.withUnsafeMutableBytes { (pointer: UnsafeMutableRawBufferPointer) -> Int32? in
            if let serializedKeyPointer = pointer.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                return secp256k1_ecdsa_signature_serialize_der(ctx, serializedKeyPointer, &siglen, &normalizedSignature)
            }
            return nil
        }
        guard result != nil else {
            throw BitcoinSigner.Error.signError
        }
        der.count = siglen
        secp256k1_context_destroy(ctx)
        return der
    }

    public static func verifySignature(_ sigData: Data, message: Data, publicKey: Data) throws -> Bool {
        guard let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY)) else { return false }
        var signature = secp256k1_ecdsa_signature()
        var pubkey = secp256k1_pubkey()
        secp256k1_ecdsa_signature_parse_der(ctx, &signature, sigData.bytes, sigData.count)
        if secp256k1_ec_pubkey_parse(ctx, &pubkey, publicKey.bytes, publicKey.count) != 1 {
            return false
        }
        if secp256k1_ecdsa_verify(ctx, &signature, message.bytes, &pubkey) != 1 {
            return false
        }
        secp256k1_context_destroy(ctx)
        return true
    }

    public static func verifySigData(for tx: Transaction, inputIndex: Int, utxo: TransactionOutput, sigData: Data, pubKeyData: Data) throws -> Bool {
        // Hash type is one byte tacked on to the end of the signature. So the signature shouldn't be empty.
        guard !sigData.isEmpty else {
            throw ScriptMachineError.error("SigData is empty.")
        }
        // Extract hash type from the last byte of the signature.
        let helper: SignatureHashHelper
        if let hashType = BCHSighashType(rawValue: sigData.last!) {
            helper = BCHSignatureHashHelper(hashType: hashType)
        } else if let hashType = BTCSighashType(rawValue: sigData.last!) {
            helper = BTCSignatureHashHelper(hashType: hashType)
        } else {
            throw ScriptMachineError.error("Unknown sig hash type")
        }
        // Strip that last byte to have a pure signature.
        let sighash: Data = helper.createSignatureHash(of: tx, for: utxo, inputIndex: inputIndex)
        let signature: Data = sigData.dropLast()

        return try Crypto.verifySignature(signature, message: sighash, publicKey: pubKeyData)
    }
}

public enum CryptoError: Error {
    case signFailed
    case noEnoughSpace
    case signatureParseFailed
    case publicKeyParseFailed
}
