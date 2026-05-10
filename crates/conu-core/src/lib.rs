//! Core conU runtime concepts shared by binaries.

pub mod agents;
pub mod messages;
pub mod runtime;
pub mod state;

/// The product invariant every crate should preserve.
pub const PRODUCT_LAW: &str = "Agents own the conversation. conU owns the connection.";

/// A workspace component and its responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    pub responsibility: &'static str,
}

/// Static manifest for the Phase 1 workspace.
pub const COMPONENTS: &[Component] = &[
    Component {
        name: "conu-cli",
        responsibility: "human control room for runtime state and private transport flow",
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
        responsibility: "relay and bootstrap service scaffold for internet connectivity",
    },
];

/// Build a user-facing status report for scaffolded binaries.
pub fn scaffold_status(component: &str) -> String {
    format!(
        "{component}: scaffold ready; payloads remain opaque; next runtime features are tracked in plan.md"
    )
}

/// Return true when the named component is part of the Phase 1 workspace.
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
