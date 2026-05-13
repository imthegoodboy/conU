//! Core conU runtime concepts shared by binaries.

pub mod agents;
pub mod messages;
pub mod relay;
pub mod relay_delivery;
pub mod rooms;
pub mod routes;
pub mod runtime;
pub mod security;
pub mod sessions;
pub mod state;
pub mod streams;
pub mod trust;

/// The product invariant every crate should preserve.
pub const PRODUCT_LAW: &str = "Agents own the conversation. conU owns the connection.";

/// A workspace component and its responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    pub responsibility: &'static str,
}

/// Static manifest for the conU workspace.
pub const COMPONENTS: &[Component] = &[
    Component {
        name: "conu-cli",
        responsibility: "human control room for runtime state and private transport flow",
    },
    Component {
        name: "conu-sdk",
        responsibility: "typed agent-facing API over conU-owned connection surfaces",
    },
    Component {
        name: "conu-mcp",
        responsibility: "MCP stdio adapter exposing conU as payload-safe agent tools",
    },
    Component {
        name: "conud",
        responsibility: "local daemon and router for agent communication",
    },
    Component {
        name: "conu-core",
        responsibility: "shared runtime primitives and project invariants",
    },
    Component {
        name: "conu-protocol",
        responsibility: "control-plane and data-plane protocol types",
    },
    Component {
        name: "conu-relay",
        responsibility: "WebSocket relay service for blind peer-encrypted internet delivery",
    },
];

/// Build a user-facing status report for scaffolded binaries.
pub fn scaffold_status(component: &str) -> String {
    format!(
        "{component}: scaffold ready; payloads remain opaque; next runtime features are tracked in plan.md"
    )
}

/// Return true when the named component is part of the conU workspace.
pub fn has_component(name: &str) -> bool {
    COMPONENTS
        .iter()
        .any(|component| component.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_one_manifest_contains_required_components() {
        for name in [
            "conu-cli",
            "conu-sdk",
            "conu-mcp",
            "conud",
            "conu-core",
            "conu-protocol",
            "conu-relay",
        ] {
            assert!(has_component(name), "missing {name}");
        }
    }

    #[test]
    fn product_law_keeps_connection_and_conversation_separate() {
        assert!(PRODUCT_LAW.contains("conversation"));
        assert!(PRODUCT_LAW.contains("connection"));
    }
}
