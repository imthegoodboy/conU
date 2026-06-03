//! Relay endpoint URL validation shared by trust, routes, sessions, and delivery.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayEndpointError {
    Empty,
    Scheme,
    Invalid,
}

pub(crate) fn validate_relay_endpoint(value: String) -> Result<String, RelayEndpointError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RelayEndpointError::Empty);
    }
    if !value.starts_with("ws://") && !value.starts_with("wss://") {
        return Err(RelayEndpointError::Scheme);
    }
    if value.len() > 220
        || value.chars().any(char::is_whitespace)
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.contains('\\')
    {
        return Err(RelayEndpointError::Invalid);
    }

    let rest = value
        .strip_prefix("ws://")
        .or_else(|| value.strip_prefix("wss://"))
        .ok_or(RelayEndpointError::Scheme)?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    validate_authority(authority)?;
    validate_path(path)?;
    Ok(value)
}

pub(crate) fn metadata_relay_endpoint(value: &str) -> Result<String, RelayEndpointError> {
    let value = validate_relay_endpoint(value.to_string())?;
    let (scheme, rest) = value
        .strip_prefix("ws://")
        .map(|rest| ("ws://", rest))
        .or_else(|| value.strip_prefix("wss://").map(|rest| ("wss://", rest)))
        .ok_or(RelayEndpointError::Scheme)?;
    if let Some((authority, _path)) = rest.split_once('/') {
        Ok(format!("{scheme}{authority}"))
    } else {
        Ok(value)
    }
}

fn validate_authority(authority: &str) -> Result<(), RelayEndpointError> {
    if authority.is_empty() {
        return Err(RelayEndpointError::Invalid);
    }

    if let Some(host_port) = authority.strip_prefix('[') {
        let Some((host, port_suffix)) = host_port.split_once(']') else {
            return Err(RelayEndpointError::Invalid);
        };
        if host.is_empty()
            || !host.contains(':')
            || host.chars().any(char::is_whitespace)
            || host.chars().any(|character| matches!(character, '[' | ']'))
        {
            return Err(RelayEndpointError::Invalid);
        }
        if port_suffix.is_empty() {
            return Ok(());
        }
        let Some(port) = port_suffix.strip_prefix(':') else {
            return Err(RelayEndpointError::Invalid);
        };
        return validate_port(port);
    }

    if authority
        .chars()
        .any(|character| matches!(character, '[' | ']'))
    {
        return Err(RelayEndpointError::Invalid);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || host.contains(':')
        || host.chars().any(char::is_whitespace)
        || host
            .chars()
            .any(|character| matches!(character, '/' | '\\'))
    {
        return Err(RelayEndpointError::Invalid);
    }
    if let Some(port) = port {
        validate_port(port)?;
    }
    Ok(())
}

fn validate_port(port: &str) -> Result<(), RelayEndpointError> {
    if port.is_empty() || !port.parse::<u16>().is_ok_and(|port| port > 0) {
        return Err(RelayEndpointError::Invalid);
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), RelayEndpointError> {
    if path.contains('\\') {
        return Err(RelayEndpointError::Invalid);
    }
    if path
        .split('/')
        .any(|part| matches!(part, "." | "..") || part.contains('%'))
    {
        return Err(RelayEndpointError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RelayEndpointError, metadata_relay_endpoint, validate_relay_endpoint};

    #[test]
    fn relay_endpoint_validation_accepts_supported_shapes() {
        for endpoint in [
            "ws://127.0.0.1:8787",
            "wss://relay.example.com/conu",
            "wss://relay.example.com",
            "ws://[::1]:8787/relay",
        ] {
            assert_eq!(
                validate_relay_endpoint(endpoint.to_string()).as_deref(),
                Ok(endpoint)
            );
        }
    }

    #[test]
    fn relay_endpoint_validation_rejects_secret_bearing_or_malformed_urls() {
        for endpoint in [
            "",
            "https://relay.example.com/conu",
            "wss://user:secret@relay.example.com/conu",
            "wss://relay.example.com/conu?token=secret",
            "wss://relay.example.com/conu#secret",
            "wss://relay.example.com:",
            "wss://relay.example.com:notaport",
            "wss:///conu",
            "wss://relay.example.com/../admin",
            "wss://relay.example.com/%2e%2e/admin",
        ] {
            assert!(
                validate_relay_endpoint(endpoint.to_string()).is_err(),
                "{endpoint} should be rejected"
            );
        }
        assert_eq!(
            validate_relay_endpoint("".to_string()),
            Err(RelayEndpointError::Empty)
        );
        assert_eq!(
            validate_relay_endpoint("https://relay.example.com".to_string()),
            Err(RelayEndpointError::Scheme)
        );
    }

    #[test]
    fn relay_endpoint_metadata_hides_path_segments() {
        assert_eq!(
            metadata_relay_endpoint("wss://relay.example.com/conu/private-token").as_deref(),
            Ok("wss://relay.example.com")
        );
        assert_eq!(
            metadata_relay_endpoint("ws://[::1]:8787/relay").as_deref(),
            Ok("ws://[::1]:8787")
        );
        assert_eq!(
            metadata_relay_endpoint("wss://relay.example.com/").as_deref(),
            Ok("wss://relay.example.com")
        );
        assert_eq!(
            metadata_relay_endpoint("ws://127.0.0.1:8787").as_deref(),
            Ok("ws://127.0.0.1:8787")
        );
    }
}
