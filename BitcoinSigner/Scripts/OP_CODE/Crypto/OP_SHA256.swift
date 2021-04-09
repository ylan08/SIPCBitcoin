//
//  OP_SHA256.swift
//  BitcoinKit
//
//  Created by Shun Usami on 2018/08/09.
//  Copyright © 2018 BitcoinKit developers. All rights reserved.
//

import Foundation

// The input is hashed using SHA-256.
struct OpSha256: OpCodeProtocol {
    var value: UInt8 { return 0xa8 }
    var name: String { return "OP_SHA256" }

    // input : in
    // output : hash
    func mainProcess(_ context: ScriptExecutionContext) throws {
        try context.assertStackHeightGreaterThanOrEqual(1)

        let data: Data = context.stack.removeLast()
         let hash: Data = Crypto.sha256(data)
        context.stack.append(hash)
    }
}
