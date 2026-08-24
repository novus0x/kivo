pub struct Contact {
    pub identity_id: String,
    pub name: String,
    // TODO: Replace with real timestamp.
    pub known_since: u64,
}

impl Contact {
    pub fn new(identity_id: &str, name: &str) -> Self {
        Contact {
            identity_id: identity_id.to_string(),
            name: name.to_string(),
            known_since: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_contact_stores_fields() {
        let contact = Contact::new("kivo-1", "Bob");
        assert_eq!(contact.identity_id, "kivo-1");
        assert_eq!(contact.name, "Bob");
    }
}
