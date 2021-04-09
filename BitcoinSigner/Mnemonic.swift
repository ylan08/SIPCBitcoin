//
//  Mnemonic.swift
//
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

enum Mnemonic {}

// MARK: To Seed
extension Mnemonic {
    /// Pass a trivial closure: `{ _ in }` to `validateChecksum` if you would like to opt-out of checksum validation.
    static func seed(
        mnemonic words: [String],
        passphrase: String = ""
    ) throws -> Data {
        let mnemonic = words.joined(separator: " ").decomposedStringWithCompatibilityMapping.data(using: .utf8)!
        let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.data(using: .utf8)!
        let seed = try PKCS5.PBKDF2(password: mnemonic.bytes, salt: salt.bytes, iterations: 2048, keyLength: 64, variant: .sha512).calculate()
        return Data(bytes: seed, count: seed.count)
    }
}
