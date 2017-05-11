//
//  Base58.swift
//  Graphene
//
//  Created by Vinícius on 10/05/17.
//  Copyright © 2017 Bitshares Munich. All rights reserved.
//

import Foundation
import Base58

public class Base58 {
    
    public static func toBase58(bytes: [UInt8]) -> String {
        return Base58Encoding.base58WithData(NSData(bytes: bytes, length: bytes.count))
    }
    
    public static func fromBase58(base58: String) -> [UInt8]? {
        guard let data = Base58Encoding.base58ToData(base58) else {
            return nil
        }
        return data.array
    }
    
    public static func toBase58Check(var bytes: [UInt8], version: [UInt8]) -> String {
        if version.count > 1 {
            bytes = (version[1..<version.count] + bytes)
        }
        return Base58Encoding.base58CheckWithData(NSData(bytes: bytes, length: bytes.count), version: version[0])
    }
    
    public static func fromBase58Check(base58: String) -> [UInt8]? {
        guard let bytes = fromBase58(base58) else {
            return nil
        }
        let result = [UInt8](bytes[0..<bytes.count-4])
        guard [UInt8](bytes[bytes.count-4..<bytes.count]) == [UInt8](Hashes.hash256(result)[0..<4]) else {
            return nil
        }
        return result
    }
    
}
