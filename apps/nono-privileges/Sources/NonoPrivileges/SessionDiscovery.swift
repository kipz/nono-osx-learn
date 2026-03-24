import Foundation

/// A named permission group from the mediation config.
struct GroupInfo: Identifiable {
    var id: String { name }
    let name: String
    let description: String
    let requiresAuth: Bool
    let durationSecs: UInt64
    let isDefault: Bool
}

/// Parsed content of a session.json file.
struct SessionInfo: Identifiable {
    let id: UInt32
    var pid: UInt32 { id }
    let controlSocket: String
    let controlToken: String
    let startedAt: String
    let sessionDir: String
    let groups: [GroupInfo]
}

/// Scans /private/tmp/nono-session-*/session.json and returns active sessions.
func discoverSessions() -> [SessionInfo] {
    let tmpDir = URL(fileURLWithPath: "/private/tmp")
    let fm = FileManager.default

    guard let entries = try? fm.contentsOfDirectory(
        at: tmpDir,
        includingPropertiesForKeys: nil
    ) else {
        return []
    }

    return entries.compactMap { entry -> SessionInfo? in
        guard entry.lastPathComponent.hasPrefix("nono-session-") else { return nil }
        let jsonURL = entry.appendingPathComponent("session.json")
        guard let data = try? Data(contentsOf: jsonURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pid = obj["pid"] as? Int,
              let controlSocket = obj["control_socket"] as? String,
              let controlToken = obj["control_token"] as? String
        else { return nil }

        // Skip sessions whose parent process is no longer alive
        guard kill(pid_t(pid), 0) == 0 else { return nil }

        let startedAt = obj["started_at"] as? String ?? ""

        // Parse groups from session.json
        var groups: [GroupInfo] = []
        if let groupsArray = obj["groups"] as? [[String: Any]] {
            for g in groupsArray {
                guard let name = g["name"] as? String,
                      let description = g["description"] as? String
                else { continue }
                let requiresAuth = g["requires_auth"] as? Bool ?? false
                let durationSecs = g["duration_secs"] as? UInt64 ?? 0
                let isDefault = g["default"] as? Bool ?? false
                groups.append(GroupInfo(
                    name: name,
                    description: description,
                    requiresAuth: requiresAuth,
                    durationSecs: durationSecs,
                    isDefault: isDefault
                ))
            }
        }

        return SessionInfo(
            id: UInt32(pid),
            controlSocket: controlSocket,
            controlToken: controlToken,
            startedAt: startedAt,
            sessionDir: entry.path,
            groups: groups
        )
    }.sorted { $0.pid < $1.pid }
}
