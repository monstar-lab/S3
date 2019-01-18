//
//  S3+Acl.swift
//  Async
//
//  Created by MD MAZHARUL ISLAM on 31/12/18.
//

import Foundation
import Vapor


// Helper S3 extension for deleting files by their URL/path
public extension S3 {
    
    // PUT ACL for a exiting object or a bucket.
    public func putAcl(file: LocationConvertible, headers: PutAclHeader, on container: Container) throws -> Future<Void> {
        let builder = urlBuilder(for: container)
        let url = try builder.url(file: file)

        let headers = try signer.headers(for: .PUT, urlString: url.absoluteString + "?acl", headers: headers.toDictionary(), payload: .none)
        return try make(request: url, method: .PUT, headers: headers, data: emptyData(), on: container).map(to: Void.self) { response in
            try self.check(response)

            return Void()
        }
    }

    /// Delete file from S3
    public func delete(file: LocationConvertible, on container: Container) throws -> Future<Void> {
        return try delete(file: file, headers: [:], on: container)
    }

}

// for more information https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTacl.html
public enum AclPermissionHeaders: String {
    case CANNED_ACL = "x-amz-acl"
    case GRANT_READ = "x-amz-grant-read"
    case GRANT_WRITE = "x-amz-grant-write"
    case READ_ACP = "x-amz-grant-read-acp"
    case WRITE_ACP = "x-amz-grant-write-acp"
    case FULL_CONTROL = "x-amz-grant-full-control"
}

public struct PutAclHeader {
    let header: String
    let value: String

    init(header: AclPermissionHeaders, value: String) {
        self.header = header.rawValue
        self.value = value
    }

    init(header: AclPermissionHeaders, grantees: [AclGrantee: String]){
        self.header = header.rawValue
        self.value = grantees.map {grantee in
            "\(grantee.key.rawValue)=\(grantee.value)"
            }.joined(separator: ",")
    }

    func toDictionary() -> [String: String] {
        return [self.header: self.value]
    }
}

public enum AclGrantee: String {
    case ID = "id"
    case EMAIL_ADDRESS = "emailAddress"
    case URI = "uri"
}

