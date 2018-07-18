import Foundation
import Service
import HTTP
import Crypto

fileprivate let kMetadataURL = "http://169.254.169.254/latest/meta-data/iam/security-credentials"

/// S3 Client: All network calls to and from AWS' S3 servers
public final class S3Signer: Service {
    
    /// Errors
    public enum Error: Swift.Error {
        case badURL(String)
        case invalidEncoding
        case missingKeySet
    }
    
    /// S3 Configuration
    public struct Config: Service {
        
        /// AWS Access Key
        var accessKey: String? = nil
        
        /// AWS Secret Key
        var secretKey: String? = nil
        
        /// The region where S3 bucket is located.
        public let region: Region
        
        /// AWS Security Token. Used to validate temporary credentials, such as those from an EC2 Instance's IAM role
        var securityToken : String?

        /// IAM role
        var roleName: String? = nil
        
        /// AWS Service type
        let service: String = "s3"

        
        /// Initalizer
        public init(accessKey: String, secretKey: String, region: Region, securityToken: String? = nil) {
            self.accessKey = accessKey
            self.secretKey = secretKey
            self.region = region
            self.securityToken = securityToken
        }

        public init(roleName: String, region: Region) {
            self.roleName = roleName
            self.region = region
        }
    }
    
    /// Configuration
    public private(set) var config: Config

    private let refreshQueue: DispatchQueue
    private let urlSession: URLSession
    
    /// Initializer
    public init(_ config: Config) throws {
        self.config = config
        self.refreshQueue = DispatchQueue(label: "com.liveui.S3.refreshQueue")

        let sessionConfiguration = URLSessionConfiguration.default

        sessionConfiguration.timeoutIntervalForRequest = 1
        sessionConfiguration.timeoutIntervalForResource = 3

        self.urlSession = URLSession(configuration: sessionConfiguration)

        if config.roleName != nil {
            self.refreshQueue.async {
                self.refreshKeys()
            }
        }
    }

    private func refreshKeys() {
        guard
            let roleName = config.roleName,
            let url = URL(string: "\(kMetadataURL)/\(roleName)")
        else {
            return
        }

        let task = urlSession.dataTask(with: url) { data, response, error in
            defer {
                self.refreshQueue.asyncAfter(deadline: DispatchTime.now() + .seconds(1_800)) {
                    self.refreshKeys()
                }
            }

            guard let data = data else {
                return
            }

            let decoder = JSONDecoder()
            let roleMetadata = try? decoder.decode(RoleMetadata.self, from: data)

            if let role = roleMetadata {
                self.config.accessKey = role.AccessKeyId
                self.config.secretKey = role.SecretAccessKey
                self.config.securityToken = role.Token
            }
        }

        task.resume()
    }

    private struct RoleMetadata: Codable {
        let AccessKeyId: String
        let SecretAccessKey: String
        let Token: String
    }
}


extension S3Signer {
    
    /// Generates auth headers for Simple Storage Services
    public func headers(for httpMethod: HTTPMethod, urlString: URLRepresentable, region: Region? = nil, headers: [String: String] = [:], payload: Payload) throws -> HTTPHeaders {
        guard let url = urlString.convertToURL() else {
            throw Error.badURL("\(urlString)")
        }
        
        let dates = getDates(Date())
        let bodyDigest = try payload.hashed()
        let region = region ?? config.region
        var updatedHeaders = update(headers: headers, url: url, longDate: dates.long, bodyDigest: bodyDigest, region: region)
        
        if httpMethod == .PUT && payload.isBytes {
            updatedHeaders["content-md5"] = try MD5.hash(payload.bytes).base64EncodedString()
        }
        
        if httpMethod == .PUT || httpMethod == .DELETE {
            updatedHeaders["content-length"] = payload.size()
            if httpMethod == .PUT && url.pathExtension != "" {
                updatedHeaders["content-type"] = (MediaType.fileExtension(url.pathExtension) ?? .plainText).description
            }
        }
        
        updatedHeaders["authorization"] = try generateAuthHeader(httpMethod, url: url, headers: updatedHeaders, bodyDigest: bodyDigest, dates: dates, region: region)
        
        var headers = HTTPHeaders()
        for (key, value) in updatedHeaders {
            headers.add(name: key, value: value)
        }
        
        return headers
    }
    
    /// Create a pre-signed URL for later use
    public func presignedURL(for httpMethod: HTTPMethod, url: URL, expiration: Expiration, region: Region? = nil, headers: [String: String] = [:]) throws -> URL? {
        let dates = Dates(Date())
        var updatedHeaders = headers
        
        let region = region ?? config.region
        
        updatedHeaders["host"] = url.host ?? region.host
        
        let (canonRequest, fullURL) = try presignedURLCanonRequest(httpMethod, dates: dates, expiration: expiration, url: url, region: region, headers: updatedHeaders)
        
        let stringToSign = try createStringToSign(canonRequest, dates: dates, region: region)
        let signature = try createSignature(stringToSign, timeStampShort: dates.short, region: region)
        let presignedURL = URL(string: fullURL.absoluteString.appending("&x-amz-signature=\(signature)"))
        return presignedURL
    }
    
}
