//
//  Websocket.swift
//  Graphene
//
//  Created by Vinícius on 11/05/17.
//  Copyright © 2017 Bitshares Munich. All rights reserved.
//

import Foundation
import CoreFoundation
import Security

public let WebsocketDidConnectNotification = "WebsocketDidConnectNotification"
public let WebsocketDidDisconnectNotification = "WebsocketDidDisconnectNotification"
public let WebsocketDisconnectionErrorKeyName = "WebsocketDisconnectionErrorKeyName"

public protocol WebSocketDelegate: class {
    func websocketDidConnect(socket: WebSocket)
    func websocketDidDisconnect(socket: WebSocket, error: NSError?)
    func websocketDidReceiveMessage(socket: WebSocket, text: String)
    func websocketDidReceiveData(socket: WebSocket, data: Data)
}

public protocol WebSocketPongDelegate: class {
    func websocketDidReceivePong(socket: WebSocket, data: Data?)
}

open class WebSocket : NSObject, StreamDelegate {
    
    enum OpCode : UInt8 {
        case continueFrame = 0x0
        case textFrame = 0x1
        case binaryFrame = 0x2
        // 3-7 are reserved.
        case connectionClose = 0x8
        case ping = 0x9
        case pong = 0xA
        // B-F reserved.
    }
    
    public enum CloseCode : UInt16 {
        case normal                 = 1000
        case goingAway              = 1001
        case protocolError          = 1002
        case protocolUnhandledType  = 1003
        // 1004 reserved.
        case noStatusReceived       = 1005
        //1006 reserved.
        case encoding               = 1007
        case policyViolated         = 1008
        case messageTooBig          = 1009
    }
    
    public static let ErrorDomain = "WebSocket"
    
    enum InternalErrorCode: UInt16 {
        case outputStreamWriteError = 1
    }
    
    // Where the callback is executed. It defaults to the main UI thread queue.
    public var callbackQueue = DispatchQueue.main
    
    var optionalProtocols: [String]?
    
    // MARK: - Constants
    
    let headerWSUpgradeName     = "Upgrade"
    let headerWSUpgradeValue    = "websocket"
    let headerWSHostName        = "Host"
    let headerWSConnectionName  = "Connection"
    let headerWSConnectionValue = "Upgrade"
    let headerWSProtocolName    = "Sec-WebSocket-Protocol"
    let headerWSVersionName     = "Sec-WebSocket-Version"
    let headerWSVersionValue    = "13"
    let headerWSKeyName         = "Sec-WebSocket-Key"
    let headerOriginName        = "Origin"
    let headerWSAcceptName      = "Sec-WebSocket-Accept"
    let BUFFER_MAX              = 4096
    let FinMask: UInt8          = 0x80
    let OpCodeMask: UInt8       = 0x0F
    let RSVMask: UInt8          = 0x70
    let MaskMask: UInt8         = 0x80
    let PayloadLenMask: UInt8   = 0x7F
    let MaxFrameSize: Int       = 32
    let httpSwitchProtocolCode  = 101
    let supportedSSLSchemes     = ["wss", "https"]
    
    class WSResponse {
        var isFin = false
        var code: OpCode = .continueFrame
        var bytesLeft = 0
        var frameCount = 0
        var buffer: NSMutableData?
    }
    
    // MARK: - Delegates
    
    /// Responds to callback about new messages coming in over the WebSocket
    /// and also connection/disconnect messages.
    public weak var delegate: WebSocketDelegate?
    
    /// Receives a callback for each pong message recived.
    public weak var pongDelegate: WebSocketPongDelegate?
    
    
    // MARK: - Block based API.
    
    public var onConnect: ((Void) -> Void)?
    public var onDisconnect: ((NSError?) -> Void)?
    public var onText: ((String) -> Void)?
    public var onData: ((Data) -> Void)?
    public var onPong: ((Data?) -> Void)?
    
    public var headers = [String: String]()
    public var origin: String?
    public var timeout = 5
    public var isConnected: Bool {
        return connected
    }
    
    public var currentURL: URL { return url }
    
    // MARK: - Private
    
    private var url: URL
    private var inputStream: InputStream?
    private var outputStream: OutputStream?
    private var connected = false
    private var isConnecting = false
    private var writeQueue = OperationQueue()
    private var readStack = [WSResponse]()
    private var inputQueue = [Data]()
    private var fragBuffer: Data?
    private var certValidated = false
    private var didDisconnect = false
    private var readyToWrite = false
    private let mutex = NSLock()
    private let notificationCenter = NotificationCenter.default
    private var canDispatch: Bool {
        mutex.lock()
        let canWork = readyToWrite
        mutex.unlock()
        return canWork
    }
    /// The shared processing queue used for all WebSocket.
    private static let sharedWorkQueue = DispatchQueue(label: "com.vluxe.starscream.websocket", attributes: [])
    
    /// Used for setting protocols.
    public init(url: URL, protocols: [String]? = nil) {
        self.url = url
        self.origin = url.absoluteString
        if let hostUrl = URL (string: "/", relativeTo: url) {
            var origin = hostUrl.absoluteString
            origin.remove(at: origin.index(before: origin.endIndex))
            self.origin = origin
        }
        writeQueue.maxConcurrentOperationCount = 1
        optionalProtocols = protocols
    }
    
    // Used for specifically setting the QOS for the write queue.
    public convenience init(url: URL, writeQueueQOS: QualityOfService, protocols: [String]? = nil) {
        self.init(url: url, protocols: protocols)
        writeQueue.qualityOfService = writeQueueQOS
    }
    
    /**
     Connect to the WebSocket server on a background thread.
     */
    open func connect() {
        guard !isConnecting else { return }
        didDisconnect = false
        isConnecting = true
        createHTTPRequest()
    }
    
    /**
     Disconnect from the server. I send a Close control frame to the server, then expect the server to respond with a Close control frame and close the socket from its end. I notify my delegate once the socket has been closed.
     
     If you supply a non-nil `forceTimeout`, I wait at most that long (in seconds) for the server to close the socket. After the timeout expires, I close the socket and notify my delegate.
     
     If you supply a zero (or negative) `forceTimeout`, I immediately close the socket (without sending a Close control frame) and notify my delegate.
     
     - Parameter forceTimeout: Maximum time to wait for the server to close the socket.
     - Parameter closeCode: The code to send on disconnect. The default is the normal close code for cleanly disconnecting a webSocket.
     */
    open func disconnect(forceTimeout: TimeInterval? = nil, closeCode: UInt16 = CloseCode.normal.rawValue) {
        guard isConnected else { return }
        switch forceTimeout {
        case .some(let seconds) where seconds > 0:
            let milliseconds = Int(seconds * 1_000)
            callbackQueue.asyncAfter(deadline: .now() + .milliseconds(milliseconds)) { [weak self] in
                self?.disconnectStream(nil)
            }
            fallthrough
        case .none:
            writeError(closeCode)
        default:
            disconnectStream(nil)
            break
        }
    }
    
    /**
     Write a string to the websocket. This sends it as a text frame.
     
     If you supply a non-nil completion block, I will perform it when the write completes.
     
     - parameter string:        The string to write.
     - parameter completion: The (optional) completion handler.
     */
    open func write(string: String, completion: (() -> ())? = nil) {
        guard isConnected else { return }
        dequeueWrite(string.data(using: String.Encoding.utf8)!, code: .textFrame, writeCompletion: completion)
    }
    
    /**
     Write binary data to the websocket. This sends it as a binary frame.
     
     If you supply a non-nil completion block, I will perform it when the write completes.
     
     - parameter data:       The data to write.
     - parameter completion: The (optional) completion handler.
     */
    open func write(data: Data, completion: (() -> ())? = nil) {
        guard isConnected else { return }
        dequeueWrite(data, code: .binaryFrame, writeCompletion: completion)
    }
    
    open func write(ping: Data, completion: (() -> ())? = nil) {
        guard isConnected else { return }
        dequeueWrite(ping, code: .ping, writeCompletion: completion)
    }
    
    /**
     Private method that starts the connection.
     */
    private func createHTTPRequest() {
        let urlRequest = CFHTTPMessageCreateRequest(kCFAllocatorDefault, "GET" as CFString,
                                                    url as CFURL, kCFHTTPVersion1_1).takeRetainedValue()
        
        var port = url.port
        if port == nil {
            if supportedSSLSchemes.contains(url.scheme!) {
                port = 443
            } else {
                port = 80
            }
        }
        addHeader(urlRequest, key: headerWSUpgradeName, val: headerWSUpgradeValue)
        addHeader(urlRequest, key: headerWSConnectionName, val: headerWSConnectionValue)
        if let protocols = optionalProtocols {
            addHeader(urlRequest, key: headerWSProtocolName, val: protocols.joined(separator: ","))
        }
        addHeader(urlRequest, key: headerWSVersionName, val: headerWSVersionValue)
        addHeader(urlRequest, key: headerWSKeyName, val: generateWebSocketKey())
        if let origin = origin {
            addHeader(urlRequest, key: headerOriginName, val: origin)
        }
        addHeader(urlRequest, key: headerWSHostName, val: "\(url.host!):\(port!)")
        for (key, value) in headers {
            addHeader(urlRequest, key: key, val: value)
        }
    }
    
    /**
     Add a header to the CFHTTPMessage by using the NSString bridges to CFString
     */
    private func addHeader(_ urlRequest: CFHTTPMessage, key: String, val: String) {
        CFHTTPMessageSetHeaderFieldValue(urlRequest, key as CFString, val as CFString)
    }
    
    /**
     Generate a WebSocket key as needed in RFC.
     */
    private func generateWebSocketKey() -> String {
        var key = ""
        let seed = 16
        for _ in 0..<seed {
            let uni = UnicodeScalar(UInt32(97 + arc4random_uniform(25)))
            key += "\(Character(uni!))"
        }
        let data = key.data(using: String.Encoding.utf8)
        let baseKey = data?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
        return baseKey!
    }
    
    /**
     Delegate for the stream methods. Processes incoming bytes
     */
    open func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        if eventCode == .hasBytesAvailable {
            if aStream == inputStream {
                processInputStream()
            }
        } else if eventCode == .errorOccurred {
            disconnectStream(aStream.streamError as NSError?)
        } else if eventCode == .endEncountered {
            disconnectStream(nil)
        }
    }
    
    /**
     Disconnect the stream object and notifies the delegate.
     */
    private func disconnectStream(_ error: NSError?, runDelegate: Bool = true) {
        if error == nil {
            writeQueue.waitUntilAllOperationsAreFinished()
        } else {
            writeQueue.cancelAllOperations()
        }
        cleanupStream()
        connected = false
        if runDelegate {
            doDisconnect(error)
        }
    }
    
    /**
     cleanup the streams.
     */
    private func cleanupStream() {
        outputStream?.delegate = nil
        inputStream?.delegate = nil
        if let stream = inputStream {
            CFReadStreamSetDispatchQueue(stream, nil)
            stream.close()
        }
        if let stream = outputStream {
            CFWriteStreamSetDispatchQueue(stream, nil)
            stream.close()
        }
        outputStream = nil
        inputStream = nil
        fragBuffer = nil
    }
    
    /**
     Handles the incoming bytes and sending them to the proper processing method.
     */
    private func processInputStream() {
        let buf = NSMutableData(capacity: BUFFER_MAX)
        let buffer = UnsafeMutableRawPointer(mutating: buf!.bytes).assumingMemoryBound(to: UInt8.self)
        let length = inputStream!.read(buffer, maxLength: BUFFER_MAX)
        guard length > 0 else { return }
        var process = false
        if inputQueue.count == 0 {
            process = true
        }
        inputQueue.append(Data(bytes: buffer, count: length))
    }
    

    /**
     Read a 16 bit big endian value from a buffer
     */
    private static func readUint16(_ buffer: UnsafePointer<UInt8>, offset: Int) -> UInt16 {
        return (UInt16(buffer[offset + 0]) << 8) | UInt16(buffer[offset + 1])
    }
    
    /**
     Read a 64 bit big endian value from a buffer
     */
    private static func readUint64(_ buffer: UnsafePointer<UInt8>, offset: Int) -> UInt64 {
        var value = UInt64(0)
        for i in 0...7 {
            value = (value << 8) | UInt64(buffer[offset + i])
        }
        return value
    }
    
    /**
     Write a 16-bit big endian value to a buffer.
     */
    private static func writeUint16(_ buffer: UnsafeMutablePointer<UInt8>, offset: Int, value: UInt16) {
        buffer[offset + 0] = UInt8(value >> 8)
        buffer[offset + 1] = UInt8(value & 0xff)
    }
    
    /**
     Write a 64-bit big endian value to a buffer.
     */
    private static func writeUint64(_ buffer: UnsafeMutablePointer<UInt8>, offset: Int, value: UInt64) {
        for i in 0...7 {
            buffer[offset + i] = UInt8((value >> (8*UInt64(7 - i))) & 0xff)
        }
    }
    
    /**
     Process the finished response of a buffer.
     */
    private func processResponse(_ response: WSResponse) -> Bool {
        if response.isFin && response.bytesLeft <= 0 {
            if response.code == .ping {
                let data = response.buffer! // local copy so it is perverse for writing
                dequeueWrite(data as Data, code: .pong)
            } else if response.code == .textFrame {
                let str: NSString? = NSString(data: response.buffer! as Data, encoding: String.Encoding.utf8.rawValue)
                if str == nil {
                    writeError(CloseCode.encoding.rawValue)
                    return false
                }
                if canDispatch {
                    callbackQueue.async { [weak self] in
                        guard let s = self else { return }
                        s.onText?(str! as String)
                        s.delegate?.websocketDidReceiveMessage(socket: s, text: str! as String)
                    }
                }
            } else if response.code == .binaryFrame {
                if canDispatch {
                    let data = response.buffer! // local copy so it is perverse for writing
                    callbackQueue.async { [weak self] in
                        guard let s = self else { return }
                        s.onData?(data as Data)
                        s.delegate?.websocketDidReceiveData(socket: s, data: data as Data)
                    }
                }
            }
            readStack.removeLast()
            return true
        }
        return false
    }
    
    /**
     Create an error
     */
    private func errorWithDetail(_ detail: String, code: UInt16) -> NSError {
        var details = [String: String]()
        details[NSLocalizedDescriptionKey] =  detail
        return NSError(domain: WebSocket.ErrorDomain, code: Int(code), userInfo: details)
    }
    
    /**
     Write an error to the socket
     */
    private func writeError(_ code: UInt16) {
        let buf = NSMutableData(capacity: MemoryLayout<UInt16>.size)
        let buffer = UnsafeMutableRawPointer(mutating: buf!.bytes).assumingMemoryBound(to: UInt8.self)
        WebSocket.writeUint16(buffer, offset: 0, value: code)
        dequeueWrite(Data(bytes: buffer, count: MemoryLayout<UInt16>.size), code: .connectionClose)
    }
    
    /**
     Used to write things to the stream
     */
    private func dequeueWrite(_ data: Data, code: OpCode, writeCompletion: (() -> ())? = nil) {
        let operation = BlockOperation()
        operation.addExecutionBlock { [weak self, weak operation] in
            //stream isn't ready, let's wait
            guard let s = self else { return }
            guard let sOperation = operation else { return }
            var offset = 2
            let dataLength = data.count
            let frame = NSMutableData(capacity: dataLength + s.MaxFrameSize)
            let buffer = UnsafeMutableRawPointer(frame!.mutableBytes).assumingMemoryBound(to: UInt8.self)
            buffer[0] = s.FinMask | code.rawValue
            if dataLength < 126 {
                buffer[1] = CUnsignedChar(dataLength)
            } else if dataLength <= Int(UInt16.max) {
                buffer[1] = 126
                WebSocket.writeUint16(buffer, offset: offset, value: UInt16(dataLength))
                offset += MemoryLayout<UInt16>.size
            } else {
                buffer[1] = 127
                WebSocket.writeUint64(buffer, offset: offset, value: UInt64(dataLength))
                offset += MemoryLayout<UInt64>.size
            }
            buffer[1] |= s.MaskMask
            let maskKey = UnsafeMutablePointer<UInt8>(buffer + offset)
            _ = SecRandomCopyBytes(kSecRandomDefault, Int(MemoryLayout<UInt32>.size), maskKey)
            offset += MemoryLayout<UInt32>.size
            
            for i in 0..<dataLength {
                buffer[offset] = data[i] ^ maskKey[i % MemoryLayout<UInt32>.size]
                offset += 1
            }
            var total = 0
            while !sOperation.isCancelled {
                guard let outStream = s.outputStream else { break }
                let writeBuffer = UnsafeRawPointer(frame!.bytes+total).assumingMemoryBound(to: UInt8.self)
                let len = outStream.write(writeBuffer, maxLength: offset-total)
                if len < 0 {
                    var error: Error?
                    if let streamError = outStream.streamError {
                        error = streamError
                    } else {
                        let errCode = InternalErrorCode.outputStreamWriteError.rawValue
                        error = s.errorWithDetail("output stream error during write", code: errCode)
                    }
                    s.doDisconnect(error as NSError?)
                    break
                } else {
                    total += len
                }
                if total >= offset {
                    if let queue = self?.callbackQueue, let callback = writeCompletion {
                        queue.async {
                            callback()
                        }
                    }
                    
                    break
                }
            }
        }
        writeQueue.addOperation(operation)
    }
    
    /**
     Used to preform the disconnect delegate
     */
    private func doDisconnect(_ error: NSError?) {
        guard !didDisconnect else { return }
        didDisconnect = true
        isConnecting = false
        connected = false
        guard canDispatch else {return}
        callbackQueue.async { [weak self] in
            guard let s = self else { return }
            s.onDisconnect?(error)
            s.delegate?.websocketDidDisconnect(socket: s, error: error)
            let userInfo = error.map{ [WebsocketDisconnectionErrorKeyName: $0] }
            s.notificationCenter.post(name: NSNotification.Name(WebsocketDidDisconnectNotification), object: self, userInfo: userInfo)
        }
    }
    
    // MARK: - Deinit
    
    deinit {
        mutex.lock()
        readyToWrite = false
        mutex.unlock()
        cleanupStream()
        writeQueue.cancelAllOperations()
    }
    
}
