//
//  main.swift
//  ask-pass-touchid
//
//  Created by Liam Brandt on 5/31/25.
//

import Foundation
import LocalAuthentication
import Security
import AppKit

// Debug logging function that writes to a file
func debugLog(_ message: String) {
    let logFile = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/ask-pass-touchid.log").path
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let logMessage = "\(timestamp) \(message)\n"
    
    // Create log file if it doesn't exist
    if !FileManager.default.fileExists(atPath: logFile) {
        FileManager.default.createFile(atPath: logFile, contents: nil)
    }
    
    do {
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: logFile))
        handle.seekToEndOfFile()
        handle.write(logMessage.data(using: .utf8)!)
        handle.closeFile()
    } catch {
        // If we can't write to the log file, write to stderr as fallback
        FileHandle.standardError.write("Error writing to log: \(error)\n".data(using: .utf8)!)
        FileHandle.standardError.write(logMessage.data(using: .utf8)!)
    }
}

class KeychainAccess {
    private let service = "SSH_SK_PIN"
    
    func hasPin(keyId: String) -> Bool {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: keyId,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as [String: Any]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    
    /// Callers must authenticate the user before reading the PIN.
    func readPin(keyId: String) -> String? {
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: keyId,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as [String: Any]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        switch status {
        case errSecSuccess:
            if let data = result as? Data,
               let pin = String(data: data, encoding: .utf8) {
                debugLog("Successfully retrieved PIN from keychain")
                return pin
            }
            debugLog("Failed to convert keychain data to string")
            return nil
            
        case errSecItemNotFound:
            debugLog("No PIN found in keychain")
            return nil
            
        default:
            debugLog("Failed to retrieve PIN from keychain: \(SecCopyErrorMessageString(status, nil) ?? "Unknown error" as CFString)")
            return nil
        }
    }
    
    /// The user just typed the PIN, so no extra authentication is needed to store it.
    func storePin(_ pin: String, keyId: String) -> Bool {
        // Replace any existing PIN
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: keyId
        ] as [String: Any]
        
        let deleteStatus = SecItemDelete(query as CFDictionary)
        if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
            debugLog("Warning: Failed to delete existing PIN: \(SecCopyErrorMessageString(deleteStatus, nil) ?? "Unknown error" as CFString)")
        }
        
        // Now store the new PIN
        let attributes = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: keyId,
            kSecValueData: pin.data(using: .utf8)!,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ] as [String: Any]
        
        let status = SecItemAdd(attributes as CFDictionary, nil)
        
        switch status {
        case errSecSuccess:
            debugLog("Successfully stored PIN in keychain")
            return true
            
        case errSecDuplicateItem:
            debugLog("PIN already exists in keychain")
            return false
            
        default:
            debugLog("Failed to store PIN in keychain: \(SecCopyErrorMessageString(status, nil) ?? "Unknown error" as CFString)")
            return false
        }
    }
}

/// Touch ID, with the system's own login-password fallback ("Use Password…").
func authenticateUser(reason: String) -> Bool {
    let context = LAContext()
    var error: NSError?
    
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        debugLog("Authentication not available: \(error?.localizedDescription ?? "unknown error")")
        return false
    }
    
    let semaphore = DispatchSemaphore(value: 0)
    var success = false
    
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { result, error in
        success = result
        if let error = error {
            debugLog("Authentication error: \(error.localizedDescription)")
        }
        semaphore.signal()
    }
    
    semaphore.wait()
    return success
}

let authenticateFlag = "--authenticate"

/// macOS titles the Touch ID sheet "<calling executable> is trying to <reason>.", and that
/// prefix can't be customised. To put the requesting app's name there, run the check from a
/// copy of this binary named after the app, e.g. "Terminal is trying to use your SSH key PIN…".
func authenticateUser(as appName: String, reason: String) -> Bool {
    guard let executable = namedCopy(of: appName) else {
        return authenticateUser(reason: reason)
    }
    
    let process = Process()
    process.executableURL = executable
    process.arguments = [authenticateFlag, reason]
    do {
        try process.run()
    } catch {
        debugLog("Failed to launch authenticator as \(appName): \(error.localizedDescription)")
        return authenticateUser(reason: reason)
    }
    process.waitUntilExit()
    return process.terminationStatus == 0
}

/// Returns ~/Library/Caches/ask-pass-touchid/<appName>, refreshed whenever this binary changes.
func namedCopy(of appName: String) -> URL? {
    let name = appName.replacingOccurrences(of: "/", with: "-").trimmingCharacters(in: .whitespacesAndNewlines)
    guard !name.isEmpty, !name.hasPrefix("."), let selfPath = Bundle.main.executablePath else { return nil }
    
    let fileManager = FileManager.default
    let directory = fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches/ask-pass-touchid")
    let destination = directory.appendingPathComponent(name)
    
    guard let current = fileManager.contents(atPath: selfPath) else { return nil }
    if fileManager.contents(atPath: destination.path) == current {
        return destination
    }
    
    do {
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        // Write to a unique temp file and rename, so concurrent askpass runs never see a partial copy.
        let temporary = directory.appendingPathComponent(".\(name).\(getpid())")
        try current.write(to: temporary)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: temporary.path)
        guard rename(temporary.path, destination.path) == 0 else {
            try? fileManager.removeItem(at: temporary)
            return nil
        }
        return destination
    } catch {
        debugLog("Failed to create authenticator copy for \(name): \(error.localizedDescription)")
        return nil
    }
}

/// Yes/no questions such as accepting an unknown host key. Cancel is the default button
/// so pressing Return never accepts a new host key by accident.
func showConfirmationDialog(prompt: String, requester: RequestingProcess?) -> Bool {
    let alert = NSAlert()
    let isHostKey = prompt.contains("continue connecting")
    let title = isHostKey ? "Unknown SSH Host" : "SSH Confirmation"
    if let requester {
        alert.messageText = "\(title) for \(requester.displayName)"
        alert.informativeText = "\(prompt)\n\n\(requester.dialogDetails)"
        if let icon = requester.appIcon {
            alert.icon = icon
        }
    } else {
        alert.messageText = title
        alert.informativeText = "\(prompt)\n\nRequesting application: unknown"
    }
    alert.alertStyle = isHostKey ? .warning : .informational
    alert.addButton(withTitle: "Cancel")
    alert.addButton(withTitle: isHostKey ? "Connect" : "Yes")
    
    NSApplication.shared.activate(ignoringOtherApps: true)
    return alert.runModal() == .alertSecondButtonReturn
}

func showSecureInputDialog(title: String, prompt: String, requester: RequestingProcess?) -> String? {
    let alert = NSAlert()
    if let requester {
        alert.messageText = "\(title) for \(requester.displayName)"
        alert.informativeText = "\(prompt)\n\n\(requester.dialogDetails)"
        if let icon = requester.appIcon {
            alert.icon = icon
        }
    } else {
        alert.messageText = title
        alert.informativeText = "\(prompt)\n\nRequesting application: unknown"
    }
    alert.alertStyle = .informational
    
    let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
    alert.accessoryView = input
    alert.addButton(withTitle: "OK")
    alert.addButton(withTitle: "Cancel")
    
    // Activate the app to ensure the alert appears
    NSApplication.shared.activate(ignoringOtherApps: true)
    
    // Observe when the window becomes key to focus the input field
    var observer: NSObjectProtocol?
    let alertWindowRef = alert.window
    observer = NotificationCenter.default.addObserver(
        forName: NSWindow.didBecomeKeyNotification,
        object: alertWindowRef,
        queue: .main
    ) { notification in
        if let window = notification.object as? NSWindow {
            window.makeFirstResponder(input)
            input.selectText(nil)
            if let observer = observer {
                NotificationCenter.default.removeObserver(observer)
            }
        }
    }
    
    // Also try to focus immediately after a short delay
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
        alertWindowRef.makeFirstResponder(input)
        input.selectText(nil)
    }
    
    // Use runModal for better focus control
    let response = alert.runModal()
    
    // Clean up observer if still active
    if let observer = observer {
        NotificationCenter.default.removeObserver(observer)
    }
    
    return response == .alertFirstButtonReturn ? input.stringValue : nil
}

func extractKeyId(from prompt: String) -> String? {
    debugLog("Extracting key ID from prompt: \(prompt)")
    
    // Try to match SHA256 format first
    if let range = prompt.range(of: "SHA256:") {
        let afterSha = String(prompt[range.upperBound...])
        if let endRange = afterSha.range(of: ":") {
            let keyId = String(afterSha[..<endRange.lowerBound]).trimmingCharacters(in: .whitespaces)
            debugLog("Extracted SHA256 key ID: \(keyId)")
            return keyId
        }
        // If no colon found, take the rest of the string
        let keyId = afterSha.trimmingCharacters(in: .whitespaces)
        debugLog("Extracted SHA256 key ID: \(keyId)")
        return keyId
    }
    
    // Fallback to matching "key /path/to/key"
    if let range = prompt.range(of: "key ") {
        let afterKey = String(prompt[range.upperBound...])
        if let colonRange = afterKey.range(of: ":") {
            let keyPath = String(afterKey[..<colonRange.lowerBound]).trimmingCharacters(in: .whitespaces)
            debugLog("Extracted key path: \(keyPath)")
            return keyPath
        }
    }
    
    debugLog("Failed to extract key ID from prompt")
    return nil
}

// Internal mode used by authenticateUser(as:reason:)
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == authenticateFlag {
    exit(authenticateUser(reason: CommandLine.arguments[2]) ? 0 : 1)
}

// Initialize logging
debugLog("=== Starting new session ===")
debugLog("Arguments: \(CommandLine.arguments)")

if CommandLine.arguments.count < 2 {
    debugLog("Error: No prompt provided")
    print("Usage: ask-pass-touchid <prompt>")
    exit(1)
}

let prompt = CommandLine.arguments[1]
debugLog("Processing prompt: \(prompt)")

let requester = RequestingProcess.identify()
if let requester {
    debugLog("Requested by: \(requester.displayName) | command: \(requester.action) | chain: \(requester.chainDescription)")
} else {
    debugLog("Requested by: unknown")
}

/// Shows Touch ID titled with the requesting app, e.g. "Terminal is trying to use your SSH key PIN for git push origin main."
func authenticateForRequester(_ purpose: String) -> Bool {
    guard let requester else {
        return authenticateUser(reason: "\(purpose) for an unknown process")
    }
    return authenticateUser(as: requester.displayName, reason: "\(purpose) for \(requester.action)")
}

// Initialize the application
NSApplication.shared.setActivationPolicy(.accessory)

if prompt.contains("Enter PIN") && prompt.contains("ED25519-SK") {
    debugLog("PIN prompt detected")
    let keychain = KeychainAccess()
    let keyId = extractKeyId(from: prompt)
    
    if let keyId, keychain.hasPin(keyId: keyId) {
        // A PIN is stored: unlock it or cancel. Don't fall back to the PIN dialog,
        // which would just lead to a second prompt.
        guard authenticateForRequester("use your SSH key PIN") else {
            debugLog("Authentication failed or cancelled")
            exit(1)
        }
        if let storedPin = keychain.readPin(keyId: keyId) {
            debugLog("Retrieved stored PIN for key: \(keyId)")
            print(storedPin)
            debugLog("PIN output successfully")
            exit(0)
        }
    }
    
    debugLog("No stored PIN found - prompting user")
    if let pin = showSecureInputDialog(title: "SSH Key PIN Required", prompt: prompt, requester: requester) {
        debugLog("User entered PIN")
        if let keyId {
            if keychain.storePin(pin, keyId: keyId) {
                debugLog("Successfully stored PIN in keychain")
            } else {
                debugLog("Failed to store PIN in keychain")
            }
        }
        print(pin)
        debugLog("PIN output successfully")
        exit(0)
    } else {
        debugLog("User cancelled PIN entry")
        exit(1)
    }
} else if prompt.contains("Confirm user presence") {
    // ssh-sk-helper launches this as a notification (SSH_ASKPASS_PROMPT=none) alongside
    // the PIN prompt and never reads the answer; the YubiKey touch is the confirmation.
    // Showing Touch ID here produced a second, stacked prompt.
    debugLog("User presence notification - touch the security key (no Touch ID needed)")
    exit(0)
} else if prompt.contains("(yes/no") {
    // e.g. "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
    debugLog("Yes/no prompt detected")
    if showConfirmationDialog(prompt: prompt, requester: requester) {
        debugLog("User answered yes")
        print("yes")
    } else {
        debugLog("User answered no")
        print("no")
    }
    exit(0)
} else if prompt.lowercased().contains("password") || prompt.contains("'s password:") {
    // Handle regular SSH password prompts
    debugLog("Password prompt detected")
    if let password = showSecureInputDialog(title: "SSH Password Required", prompt: prompt, requester: requester) {
        debugLog("User entered password")
        print(password)
        debugLog("Password output successfully")
        exit(0)
    } else {
        debugLog("User cancelled password entry")
        exit(1)
    }
} else {
    debugLog("Unknown prompt type")
    exit(1)
}

