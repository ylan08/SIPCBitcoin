//
//  BitcoinSignerTests.swift
//  BitcoinSignerTests
//
//  Created by 翟泉 on 2020/8/25.
//  Copyright © 2020 cezres. All rights reserved.
//

import XCTest
@testable import BitcoinSigner

class BitcoinSignerTests: XCTestCase {
    
    func testExample() throws {
        let res = try BitcoinSigner.publicKey(with: "seed sock milk update focus rotate barely fade car face mechanic mercy".components(separatedBy: " "), network: .testnetBTC, derivationPath: "m/49'/1'/0'/0/0")
        print(res)
    }

    func testPublicKey() throws {
        XCTAssertEqual(try BitcoinSigner.publicKey(with: "talk wonder pilot other element hair draw learn icon expire cook ginger".components(separatedBy: " "), network: .testnetBTC, derivationPath: "m/49'/1'/0'/0/0"), "upub5HyCpoMxHiarX7Uvt1U5WtaqPGDxusvcbf8sMpTTTkWhgbVzMVJ46daRkV2QQaydFiV7E2aYSRUZZjdHjja5ddywYnMpUwX8qY4eo6X6H5b")
        XCTAssertEqual(try BitcoinSigner.publicKey(with: "travel label harvest demise february device cushion sign soap horn team giggle relax frost flat".components(separatedBy: " "), network: .testnetBTC, derivationPath: "m/49'/1'/0'/0/1"), "upub5Had3m5YpcssattsNVK3c9LqMmepaDubYbvnx8qemZWwNcrjryqqSAKN8p7S3c32qzaWGgCAYHL6TuNg5aoSqGLaaLWeGxDKrRnGBe1MmTu")
    }

    func testWitnessSignatureP2SH_P2WPKH() throws {
        let mnemonic = "travel label harvest demise february device cushion sign soap horn team giggle relax frost flat".components(separatedBy: " ")
        let derivationPath = "m/49'/1'/0'/0/1"
        let rawTransaction = "0100000001e6638c113bd2e3d1381df6ac26d97392d141dfe7660092d3162790162b9ebefd0100000000ffffffff02983a00000000000017a9141d018b91067a31c039f324778c905caae808a1158714e900000000000017a914f211abebccea466dc5f7d7f17e50d5cd68fb655e8700000000"
        let inputValues: [UInt64] = [74834]

        let result = try BitcoinSigner.signatureBitcoinTransaction(for: rawTransaction, inputValues: inputValues, mnemonic: mnemonic, network: .mainnetBTC, derivationPath: derivationPath)
        XCTAssertEqual(result, "01000000000101e6638c113bd2e3d1381df6ac26d97392d141dfe7660092d3162790162b9ebefd010000001716001485a78d41d073525afeed3c977e0c2e7d6dff76beffffffff02983a00000000000017a9141d018b91067a31c039f324778c905caae808a1158714e900000000000017a914f211abebccea466dc5f7d7f17e50d5cd68fb655e87024830450221008be94f5b0ace6710ea474cbaaf56fd0d6645627747183388809e3985f18edfc602205214c0814feeeeebb9dcf598a41ab978a2906df33adfea92f22b6e6ab17b937f01210259515492a9e114a08d51c2b37ebb8cfb7349e5bc5ee4782eed2a4eaf9f51f2ec00000000")
    }

    func testtestWitnessSignatureP2SH_P2WPKH2() throws {
        let mnemonic = "kangaroo test remember require recipe finger brass winter broom artist chalk space".components(separatedBy: " ")
        let derivationPath = "m/49'/1'/0'/0/0"
        let rawTransaction = "01000000024789668ea9d65618ed0fa7252c1be0b4fc1866d6331127d4896f000e5eca807c0100000000ffffffff06a7f2e02b17cd45caa68888925f5fd5202cecd319bcb92fdf0168b5f69f2d0c0100000000ffffffff02401f00000000000017a91423fbbfd2d5a290923b44cadeb579076bcb2c2327876f0800000000000017a9148e7d616c38bcc9457508b22c18f2c1bbb49a9de88700000000"
        let inputValues: [UInt64] = [7683, 2734]

        let result = try BitcoinSigner.signatureBitcoinTransaction(for: rawTransaction, inputValues: inputValues, mnemonic: mnemonic, network: .testnetBTC, derivationPath: derivationPath)
        XCTAssertEqual(result, "010000000001024789668ea9d65618ed0fa7252c1be0b4fc1866d6331127d4896f000e5eca807c010000001716001406f751a1f01bbc86b3b948d538bdca1433772736ffffffff06a7f2e02b17cd45caa68888925f5fd5202cecd319bcb92fdf0168b5f69f2d0c010000001716001406f751a1f01bbc86b3b948d538bdca1433772736ffffffff02401f00000000000017a91423fbbfd2d5a290923b44cadeb579076bcb2c2327876f0800000000000017a9148e7d616c38bcc9457508b22c18f2c1bbb49a9de88702483045022100f7caf78014dc473966db694deaf9739ba43ab58d4836a7363f20865faee855960220407cf37d6160ddbcde9e65fb767896f4aed92b07c124e4bff9730d85a609955e01210211bd51d7307ff2cf96eb42f7235c1d9a813640cba1018992d7968181b90a3ffd024730440220315c1135287777a81b2e230fe8104aacf85f7a657f89c7c887f5647fdda341e7022047971cd403758930465af46fa60dd339759ce4d35d0d409ff585d81a672f18a301210211bd51d7307ff2cf96eb42f7235c1d9a813640cba1018992d7968181b90a3ffd00000000")
    }

    func testWitnessSignatureP2SH_P2WSH() throws {
        let mnemonic = "amount hungry mail leave spawn carbon cattle evoke timber second furnace wife".components(separatedBy: " ")
        let derivationPath = "m/49'/1'/0'/0/0"
        let rawTransaction = "01000000011b7465be2059236d9c7cbefe579bcdb4cb61f0a95576ae00616e169de14239850000000000ffffffff02983a00000000000017a9147d4188a878a8a1c7d877ed7132c954858b1dbfb1870ad600000000000017a914e7d1dd77fb10a5dfd9c4d2bedaa0c0ab13d6327f8700000000"
        let inputValues: [UInt64] = [70000]
        let extendedPublicKeys = [
            "upub5JaZTDcusCwiy8N4biFn9hq7UPZtLHLTRY1aURU9UfEKibWMDEVg4Sbnowj6qPQnKqjgMAiJhTAkq5Wx4Yu1JvEaw45XxqvAHnzKt7wJwti",
            "upub5GyARati4n1bby2oZJcCkPEG6LXJNwceHjqV57hHKgH2YqKXi2KMD5bFbhMc6ykxHVX2tvT9dVXnAMgpyCYoN8yuLPb4Rc3UMt2W6wZkfji",
        ]
        let signaturesRequired: UInt = 2

        let result = try BitcoinSigner.signatureBitcoinTransaction(for: rawTransaction, inputValues: inputValues, extendedPublicKeys: extendedPublicKeys, signaturesRequired: signaturesRequired, mnemonic: mnemonic, network: .testnetBTC, derivationPath: derivationPath)

        XCTAssertEqual(result, [["304502210090d2e70d611e689c9fc434ebabc88fe0b78efa59d724d696fc98f459dcdf521902207ee65e44668a587e3531f5788b4a9fdfd88fa678a02f11f61829ea02c566e7a001"]])
    }

    func testWitnessSignatureP2SH_P2WSH2() throws {
        let mnemonic = "talk wonder pilot other element hair draw learn icon expire cook ginger".components(separatedBy: " ")
        let derivationPath = "m/49'/0'/0'/0/0"
        let rawTransaction = "01000000019d1744958dcf5bbddee61eca8ce280e21b74b6a481a5038d3e8cf1b828ba249f0000000000ffffffff02d00700000000000017a914a8efd8024195c6294a5d8d08f1aa9199fd044f64871a0300000000000017a9147adf50f8f5d936048b4968255f14416ea82b40eb8700000000"
        let inputValues: [UInt64] = [3000]
        let extendedPublicKeys = [
            "upub5JSWDoNdtTu6w7xgkhDWhSPJYdR2he4jYY2j7fcmdKVZn2umNH739LEr8b6K9yTxg1nP7xoUZEJRWT677YQ5P3E5HsnmA8c3TcWCRXQ3PbD",
            "upub5JmM5wBsT5WHdPjAgSAiet5kGYpvzoMpzYy9yhN5jvn2RfjEsg2Xh6gaFvyWufEu2KHTZEHj5wJXiSVoCBMoj8w3ebEwk3nJtw5Az62p63v",
        ]
        let signaturesRequired: UInt = 2

        let result = try BitcoinSigner.signatureBitcoinTransaction(for: rawTransaction, inputValues: inputValues, extendedPublicKeys: extendedPublicKeys, signaturesRequired: signaturesRequired, mnemonic: mnemonic, network: .testnetBTC, derivationPath: derivationPath)

        XCTAssertEqual(result, [["3045022100a78b06f0dfa93b525b8d6f23dccadb24ed866dc84081e03922bde4f419c0859d02202fab29b31601802fd6383aad56be6577f9a9be3f978348d465dfb0f00494603801"]])
    }

    func testLitecoinPublicKey() throws {
        let mnemonic = "stairs talk sudden palace trip chest want strike high range strategy critic gasp gesture edge"
//        let mnemonic = "address total lift home orbit shift scene trust field stick glove because clump zebra romance"
        let derivationPath = "m/49'/2'/0'/0/0"

        let pubkey = try LitecoinSigner.publicKey(with: mnemonic.components(separatedBy: " "), network: .testnetLTC, derivationPath: derivationPath)
        print(pubkey)
    }

    func testLitecoinSignature() throws {
        let mnemonic = "kangaroo test remember require recipe finger brass winter broom artist chalk space".components(separatedBy: " ")
        let derivationPath = "m/49'/1'/0'/0/0"

        let raw = "0100000001f88e16dbfb1e56b6bce02f7ed38dd7b630c976c53ffb7d351de79abd903161940000000000ffffffff02a08601000000000017a914ff545188d3a6bbbc7cd8d74b8ecfcb44bb67914687b2365a050000000017a9148e7d616c38bcc9457508b22c18f2c1bbb49a9de88700000000"


        let inputValues: [UInt64] = [89898488]

        let result = try LitecoinSigner.signatureTransaction(for: raw, inputValues: inputValues, mnemonic: mnemonic, network: .testnetLTC, derivationPath: derivationPath)
//        let result = try LitecoinSigner.signatureBitcoinTransaction(for: raw, inputValues: inputValues, mnemonic: mnemonic, network: .testnetLTC, derivationPath: derivationPath)
        print(result)
        XCTAssertEqual(result, "010000000001024789668ea9d65618ed0fa7252c1be0b4fc1866d6331127d4896f000e5eca807c010000001716001406f751a1f01bbc86b3b948d538bdca1433772736ffffffff06a7f2e02b17cd45caa68888925f5fd5202cecd319bcb92fdf0168b5f69f2d0c010000001716001406f751a1f01bbc86b3b948d538bdca1433772736ffffffff02401f00000000000017a91423fbbfd2d5a290923b44cadeb579076bcb2c2327876f0800000000000017a9148e7d616c38bcc9457508b22c18f2c1bbb49a9de88702483045022100f7caf78014dc473966db694deaf9739ba43ab58d4836a7363f20865faee855960220407cf37d6160ddbcde9e65fb767896f4aed92b07c124e4bff9730d85a609955e01210211bd51d7307ff2cf96eb42f7235c1d9a813640cba1018992d7968181b90a3ffd024730440220315c1135287777a81b2e230fe8104aacf85f7a657f89c7c887f5647fdda341e7022047971cd403758930465af46fa60dd339759ce4d35d0d409ff585d81a672f18a301210211bd51d7307ff2cf96eb42f7235c1d9a813640cba1018992d7968181b90a3ffd00000000")

    }

}
