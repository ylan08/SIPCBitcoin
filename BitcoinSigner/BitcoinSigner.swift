//
//  BitcoinSigner.swift
//  BitcoinSigner
//
//  Created by 翟泉 on 2020/8/25.
//  Copyright © 2020 cezres. All rights reserved.
//

import Foundation
import CryptoSwift

public class BitcoinSigner {

    public static func publicKey(with mnemonic: [String], network: Network, derivationPath: String) throws -> String {
        let seed = try Mnemonic.seed(mnemonic: mnemonic)
        let keychain = HDKeychain(seed: seed, network: network)
        let key = try keychain.derivedKey(path: derivationPath)
        return key.extendedPublicKeyForBIP49()
    }

    public static func signatureBitcoinTransaction(for rawTransaction: String, inputValues: [UInt64], mnemonic: [String], network: Network, derivationPath: String) throws -> String {
        let seed = try Mnemonic.seed(mnemonic: mnemonic)
        let keychain = HDKeychain(seed: seed, network: network)
        let key = try keychain.derivedKey(path: derivationPath)
        let privateKey = key.privateKey()
        let rawTransaction = Data(hex: rawTransaction)
        return try TransactionSigner.witnessSignatureP2SH_P2WPKH(rawTransaction: rawTransaction, inputValues: inputValues, privateKey: privateKey).hex
    }

    public static func signatureBitcoinTransaction(for rawTransaction: String, inputValues: [UInt64], extendedPublicKeys: [String], signaturesRequired: UInt, mnemonic: [String], network: Network, derivationPath: String) throws -> [[String]] {
        let seed = try Mnemonic.seed(mnemonic: mnemonic)
        let keychain = HDKeychain(seed: seed, network: network)
        let key = try keychain.derivedKey(path: derivationPath)
        let privateKey = key.privateKey()
        let rawTransaction = Data(hex: rawTransaction)
        return try TransactionSigner.witnessSignatureP2SH_P2WSH(rawTransaction: rawTransaction, inputValues: inputValues, extendedPublicKeys: extendedPublicKeys, signaturesRequired: signaturesRequired, privateKey: privateKey)
    }
}

public class LitecoinSigner {
    public static func publicKey(with mnemonic: [String], network: Network, derivationPath: String) throws -> String {
        let seed = try Mnemonic.seed(mnemonic: mnemonic)
        let keychain = HDKeychain(seed: seed, network: network)
        let key = try keychain.derivedKey(path: derivationPath)
        return key.extendedPublicKeyForBIP49()
    }

    public static func signatureTransaction(for rawTransaction: String, inputValues: [UInt64], mnemonic: [String], network: Network, derivationPath: String) throws -> String {
        let seed = try Mnemonic.seed(mnemonic: mnemonic)
        let keychain = HDKeychain(seed: seed, network: network)
        let key = try keychain.derivedKey(path: derivationPath)
        let privateKey = key.privateKey()
        let rawTransaction = Data(hex: rawTransaction)
        return try TransactionSigner.witnessSignatureP2SH_P2WPKH(rawTransaction: rawTransaction, inputValues: inputValues, privateKey: privateKey).hex
    }

    public static func signatureTransaction(for rawTransaction: String, inputValues: [UInt64], extendedPublicKeys: [String], signaturesRequired: UInt, mnemonic: [String], network: Network, derivationPath: String) throws -> [[String]] {
        let seed = try Mnemonic.seed(mnemonic: mnemonic)
        let keychain = HDKeychain(seed: seed, network: network)
        let key = try keychain.derivedKey(path: derivationPath)
        let privateKey = key.privateKey()
        let rawTransaction = Data(hex: rawTransaction)
        return try TransactionSigner.witnessSignatureP2SH_P2WSH(rawTransaction: rawTransaction, inputValues: inputValues, extendedPublicKeys: extendedPublicKeys, signaturesRequired: signaturesRequired, privateKey: privateKey)
    }
}

extension BitcoinSigner {
    enum Error: LocalizedError {
        case signError
    }
}
