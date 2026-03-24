import SwiftUI
import LocalAuthentication

/// A button style that shows a rounded highlight on hover, working inside NSPopover.
struct MenuButtonStyle: ButtonStyle {
    var tint: Color = .primary
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: 5)
                    .fill(hovering || configuration.isPressed
                          ? tint.opacity(0.15)
                          : Color.clear)
            )
            .onHover { hovering = $0 }
            .animation(.easeInOut(duration: 0.1), value: hovering)
    }
}

/// Minimal row-level hover highlight (for Quit and refresh).
struct RowButtonStyle: ButtonStyle {
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(hovering || configuration.isPressed ? .primary : .secondary)
            .onHover { hovering = $0 }
            .animation(.easeInOut(duration: 0.1), value: hovering)
    }
}

/// Observed store for session state, polled on a timer.
class SessionStore: ObservableObject {
    @Published var sessions: [SessionInfo] = []
    @Published var sessionStatuses: [UInt32: PrivilegeStatus] = [:]

    func refresh() {
        DispatchQueue.global(qos: .utility).async {
            let discovered = discoverSessions()
            var statuses: [UInt32: PrivilegeStatus] = [:]
            for session in discovered {
                let client = ControlClient(session: session)
                if let status = try? client.status() {
                    statuses[session.pid] = status
                }
            }
            DispatchQueue.main.async {
                self.sessions = discovered
                self.sessionStatuses = statuses
            }
        }
    }

    func hasAnyActive() -> Bool {
        sessionStatuses.values.contains { $0.isActive }
    }
}

enum GroupAction {
    case disable, enableWithAuth, enable
}

/// Standalone view for a permission group row — needs its own @State for hover tracking.
struct GroupButtonView: View {
    let session: SessionInfo
    let group: GroupInfo
    let status: PrivilegeStatus?
    let onAction: (GroupAction) -> Void

    @State private var hovering = false

    var body: some View {
        let isActiveGroup = status?.activeGroup == group.name && status?.isGroup == true
        HStack(spacing: 4) {
            Image(systemName: isActiveGroup ? "checkmark.circle.fill" : "circle")
                .font(.caption2)
                .foregroundColor(isActiveGroup ? .blue : .secondary)
            Text(group.description)
                .font(.caption)
            if group.requiresAuth {
                Image(systemName: "touchid")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .contentShape(Rectangle())
        .onTapGesture {
            if isActiveGroup {
                onAction(.disable)
            } else if group.requiresAuth {
                onAction(.enableWithAuth)
            } else {
                onAction(.enable)
            }
        }
        .onHover { hovering = $0 }
        .padding(.vertical, 2)
        .padding(.horizontal, 4)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(isActiveGroup
                      ? Color.blue.opacity(0.15)
                      : hovering ? Color.primary.opacity(0.08) : Color.clear)
        )
        .animation(.easeInOut(duration: 0.1), value: hovering)
    }
}

struct MenuBarView: View {
    @ObservedObject var store: SessionStore
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "key.horizontal.fill")
                    .foregroundColor(.primary)
                Text("nono-privileges")
                    .font(.headline)
                Spacer()
                Button(action: { store.refresh() }) {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(RowButtonStyle())
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
                Divider()
            }

            if store.sessions.isEmpty {
                Text("No active sessions")
                    .foregroundColor(.secondary)
                    .font(.caption)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            } else {
                ForEach(store.sessions) { session in
                    sessionRow(session)
                    Divider()
                }
            }

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .buttonStyle(RowButtonStyle())
            .font(.caption)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .frame(width: 280)
    }

    @ViewBuilder
    private func sessionRow(_ session: SessionInfo) -> some View {
        let status = store.sessionStatuses[session.pid]
        let isActive = status?.isActive ?? false

        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(statusColor(status))
                    .frame(width: 8, height: 8)
                Text("Session \(String(session.pid))")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Spacer()
            }

            // Status line with countdown
            if let status = status, isActive {
                statusLabel(status)
            } else {
                Text("Inactive")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            // Permission group buttons — prefer status groups (from server),
            // but fall back to session groups if the status response omitted them
            // (enable/disable responses don't include the groups list).
            let groups = (status?.groups.isEmpty == false) ? status!.groups : session.groups
            if !groups.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Permission Groups")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.top, 2)

                    ForEach(groups) { group in
                        groupButton(session: session, group: group, status: status)
                    }
                }
            }

            // YOLO mode button (always requires auth)
            if status?.isYolo == true {
                Button("Disable YOLO Mode") {
                    errorMessage = nil
                    disablePrivilege(for: session)
                }
                .buttonStyle(MenuButtonStyle(tint: .red))
            } else {
                Button("Enable YOLO Mode") {
                    errorMessage = nil
                    authenticateAndEnableYolo(for: session)
                }
                .buttonStyle(MenuButtonStyle(tint: .orange))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private func statusLabel(_ status: PrivilegeStatus) -> some View {
        if status.isYolo {
            if let secs = status.secondsRemaining {
                Text("YOLO: \(secs / 60)m \(secs % 60)s remaining")
                    .font(.caption)
                    .foregroundColor(.orange)
            } else {
                Text("YOLO active")
                    .font(.caption)
                    .foregroundColor(.orange)
            }
        } else if status.isGroup, let groupName = status.activeGroup {
            if let secs = status.secondsRemaining {
                Text("\(groupName): \(secs / 60)m \(secs % 60)s remaining")
                    .font(.caption)
                    .foregroundColor(.blue)
            } else {
                Text("\(groupName) active")
                    .font(.caption)
                    .foregroundColor(.blue)
            }
        }
    }

    private func groupButton(session: SessionInfo, group: GroupInfo, status: PrivilegeStatus?) -> some View {
        GroupButtonView(session: session, group: group, status: status) { action in
            errorMessage = nil
            switch action {
            case .disable:
                disablePrivilege(for: session)
            case .enableWithAuth:
                authenticateAndEnableGroup(for: session, group: group)
            case .enable:
                enableGroup(for: session, group: group)
            }
        }
    }

    private func statusColor(_ status: PrivilegeStatus?) -> Color {
        guard let status = status, status.isActive else { return .green }
        if status.isYolo { return .orange }
        if status.isGroup { return .blue }
        return .green
    }

    private func authenticateAndEnableYolo(for session: SessionInfo) {
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError) else {
            errorMessage = authError?.localizedDescription ?? "Authentication unavailable"
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Enable YOLO mode for session \(session.pid)"
        ) { success, err in
            if success {
                DispatchQueue.global(qos: .userInitiated).async {
                    let client = ControlClient(session: session)
                    do {
                        let status = try client.enable(durationSecs: 600, grantedBy: "TouchID")
                        DispatchQueue.main.async {
                            store.sessionStatuses[session.pid] = status
                        }
                    } catch {
                        DispatchQueue.main.async {
                            errorMessage = "Enable failed: \(error)"
                            store.refresh()
                        }
                    }
                }
            } else if let err {
                DispatchQueue.main.async {
                    let lac = err as? LAError
                    if lac?.code != .userCancel {
                        errorMessage = err.localizedDescription
                    }
                }
            }
        }
    }

    private func authenticateAndEnableGroup(for session: SessionInfo, group: GroupInfo) {
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError) else {
            errorMessage = authError?.localizedDescription ?? "Authentication unavailable"
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Enable \(group.description) for session \(session.pid)"
        ) { success, err in
            if success {
                enableGroup(for: session, group: group)
            } else if let err {
                DispatchQueue.main.async {
                    let lac = err as? LAError
                    if lac?.code != .userCancel {
                        errorMessage = err.localizedDescription
                    }
                }
            }
        }
    }

    private func enableGroup(for session: SessionInfo, group: GroupInfo) {
        DispatchQueue.global(qos: .userInitiated).async {
            let client = ControlClient(session: session)
            do {
                let status = try client.enable(
                    group: group.name,
                    durationSecs: group.durationSecs,
                    grantedBy: group.requiresAuth ? "TouchID" : "App"
                )
                DispatchQueue.main.async {
                    store.sessionStatuses[session.pid] = status
                }
            } catch {
                DispatchQueue.main.async {
                    errorMessage = "Enable group failed: \(error)"
                    store.refresh()
                }
            }
        }
    }

    private func disablePrivilege(for session: SessionInfo) {
        DispatchQueue.global(qos: .userInitiated).async {
            let client = ControlClient(session: session)
            do {
                let status = try client.disable(grantedBy: "App")
                DispatchQueue.main.async {
                    store.sessionStatuses[session.pid] = status
                }
            } catch {
                DispatchQueue.main.async { store.refresh() }
            }
        }
    }
}
