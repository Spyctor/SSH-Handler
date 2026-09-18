//
//  RequestingProcess.swift
//  ask-pass-touchid
//
//  Works out which application/process caused SSH to ask for a PIN or password.
//
//  The askpass is launched by ssh, ssh-keygen or ssh-sk-helper. When the key
//  lives in ssh-agent, the chain is askpass <- ssh-sk-helper <- ssh-agent and
//  the real requester is whichever process is connected to the agent socket,
//  so we follow that socket to its peer.
//

import AppKit
import Darwin

struct ProcessDetails {
    let pid: pid_t
    let ppid: pid_t
    let name: String
    let path: String
    let arguments: [String]
    let startTime: UInt64

    init?(pid: pid_t) {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard pid > 0, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }

        self.pid = pid
        self.ppid = pid_t(info.pbi_ppid)
        self.startTime = info.pbi_start_tvsec

        var pathBuffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        self.path = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count)) > 0 ? String(cString: pathBuffer) : ""

        let arguments = ProcessDetails.arguments(of: pid)
        self.arguments = arguments

        let comm = withUnsafePointer(to: info.pbi_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: info.pbi_name)) { String(cString: $0) }
        }
        if !comm.isEmpty {
            self.name = comm
        } else if !path.isEmpty {
            self.name = (path as NSString).lastPathComponent
        } else {
            self.name = (arguments.first.map { ($0 as NSString).lastPathComponent }) ?? "pid \(pid)"
        }
    }

    /// Reads argv via KERN_PROCARGS2 (only works for processes owned by this user).
    private static func arguments(of pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return [] }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }

        let argc = buffer.withUnsafeBytes { Int($0.load(as: Int32.self)) }
        var index = MemoryLayout<Int32>.size
        // Skip the executable path and the NUL padding that follows it.
        while index < size && buffer[index] != 0 { index += 1 }
        while index < size && buffer[index] == 0 { index += 1 }

        var arguments: [String] = []
        while arguments.count < argc && index < size {
            let start = index
            while index < size && buffer[index] != 0 { index += 1 }
            arguments.append(String(decoding: buffer[start..<index], as: UTF8.self))
            index += 1
        }
        return arguments
    }

    var commandLine: String {
        guard !arguments.isEmpty else { return name }
        var parts = arguments
        parts[0] = (parts[0] as NSString).lastPathComponent
        return parts.map { $0.contains(" ") ? "'\($0)'" : $0 }.joined(separator: " ")
    }

    /// The outermost .app bundle containing this executable, e.g. Visual Studio Code.app for its helpers.
    var appBundleURL: URL? {
        guard let range = path.range(of: ".app/") else { return nil }
        return URL(fileURLWithPath: String(path[..<range.lowerBound]) + ".app")
    }
}

struct RequestingProcess {
    /// The process that talked to ssh/ssh-agent (e.g. ssh, ssh-keygen).
    let requester: ProcessDetails
    /// requester followed by its ancestors, up to (not including) launchd.
    let chain: [ProcessDetails]
    let appName: String?
    let appIcon: NSImage?

    /// Short, single-line description of the action, e.g. "git push origin main" or "ssh admin@host".
    var action: String {
        if let git = chain.first(where: { $0.name == "git" && $0.arguments.count > 1 }) {
            return gitAction(git.arguments)
        }
        if requester.name == "ssh", let target = requester.arguments.dropFirst().first(where: { $0.contains("@") }) {
            return "ssh \(target)"
        }
        return requester.name
    }

    /// "git <subcommand>", plus remote/branch for network commands. Skips options like -m "<message>".
    private func gitAction(_ arguments: [String]) -> String {
        var rest = arguments.dropFirst()
        while let first = rest.first, first.hasPrefix("-") {
            rest = rest.dropFirst(first == "-C" || first == "-c" ? 2 : 1)
        }
        guard let subcommand = rest.first else { return "git" }
        var parts = ["git", subcommand]
        if ["push", "pull", "fetch", "clone", "ls-remote"].contains(subcommand) {
            parts += rest.dropFirst().filter { !$0.hasPrefix("-") }.prefix(2)
        }
        return truncate(parts.joined(separator: " "), to: 40)
    }

    /// Who is asking, for dialog titles, e.g. "Terminal" or "ssh".
    var displayName: String { appName ?? requester.name }

    /// e.g. "ssh ← git ← zsh ← Terminal"
    var chainDescription: String {
        chain.map(\.name).joined(separator: " ← ")
    }

    var dialogDetails: String {
        var lines: [String] = []
        if let appName { lines.append("Application: \(appName)") }
        lines.append("Command: \(action)")
        lines.append("Process: \(requester.name) (pid \(requester.pid))")
        lines.append("Chain: \(truncate(chainDescription, to: 160))")
        return lines.joined(separator: "\n")
    }

    static func identify() -> RequestingProcess? {
        var ancestors: [ProcessDetails] = []
        var pid = getppid()
        while pid > 1, let details = ProcessDetails(pid: pid), ancestors.count < 64 {
            ancestors.append(details)
            pid = details.ppid
        }

        let requester: ProcessDetails
        if let agent = ancestors.first(where: { $0.name == "ssh-agent" }) {
            guard let client = agentClient(agentPid: agent.pid) else {
                debugLog("Could not find the ssh-agent client that triggered this request")
                return nil
            }
            requester = client
        } else if let direct = ancestors.first(where: { $0.name != "ssh-sk-helper" }) {
            requester = direct
        } else {
            return nil
        }

        var chain: [ProcessDetails] = []
        var current: ProcessDetails? = requester
        while let details = current, details.pid > 1, chain.count < 64 {
            chain.append(details)
            current = ProcessDetails(pid: details.ppid)
        }

        var appName: String?
        var appIcon: NSImage?
        // Use the top-most app in the chain: tools like git may live inside Xcode.app,
        // but the app the user is interacting with (Terminal, VS Code, ...) is further up.
        if let bundleURL = chain.compactMap(\.appBundleURL).last {
            let bundle = Bundle(url: bundleURL)
            appName = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)
                ?? bundleURL.deletingPathExtension().lastPathComponent
            appIcon = NSWorkspace.shared.icon(forFile: bundleURL.path)
        }

        return RequestingProcess(requester: requester, chain: chain, appName: appName, appIcon: appIcon)
    }

    /// Finds the process on the other end of ssh-agent's accepted connections.
    /// The agent's own children (ssh-sk-helper) are connected via socketpairs, so skip them.
    /// If several clients are connected, the most recently started one wins.
    private static func agentClient(agentPid: pid_t) -> ProcessDetails? {
        let peerSockets = Set(unixSockets(of: agentPid).map(\.peer).filter { $0 != 0 })
        guard !peerSockets.isEmpty else { return nil }

        var candidates: [ProcessDetails] = []
        for pid in allPids() where pid != agentPid {
            if unixSockets(of: pid).contains(where: { peerSockets.contains($0.socket) }),
               let details = ProcessDetails(pid: pid), details.ppid != agentPid {
                candidates.append(details)
            }
        }
        return candidates.max { $0.startTime < $1.startTime }
    }

    private static func allPids() -> [pid_t] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let found = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        return Array(pids.prefix(Int(max(found, 0)))).filter { $0 > 0 }
    }

    private static func unixSockets(of pid: pid_t) -> [(socket: UInt64, peer: UInt64)] {
        let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return [] }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(size) / MemoryLayout<proc_fdinfo>.stride)
        let filled = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, size)
        guard filled > 0 else { return [] }

        var sockets: [(UInt64, UInt64)] = []
        for fd in fds.prefix(Int(filled) / MemoryLayout<proc_fdinfo>.stride) where fd.proc_fdtype == PROX_FDTYPE_SOCKET {
            var info = socket_fdinfo()
            let infoSize = Int32(MemoryLayout<socket_fdinfo>.size)
            guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, infoSize) == infoSize,
                  info.psi.soi_kind == SOCKINFO_UN else { continue }
            sockets.append((info.psi.soi_so, info.psi.soi_proto.pri_un.unsi_conn_so))
        }
        return sockets
    }
}

private func truncate(_ text: String, to length: Int) -> String {
    text.count > length ? String(text.prefix(length - 1)) + "…" : text
}
