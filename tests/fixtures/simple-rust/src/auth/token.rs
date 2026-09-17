pub(crate) struct Session {
    user: String,
    token: String,
}

impl Session {
    pub(crate) fn new(user: &str, token: String) -> Self {
        Self { user: user.to_string(), token }
    }

    pub(crate) fn label(&self) -> String {
        format!("{}:{}", self.user, redact(&self.token))
    }
}

pub(crate) fn mint(user: &str) -> String {
    let mut out = String::from(user);
    out.push_str("-token");
    out
}

fn redact(secret: &str) -> String {
    secret.chars().take(2).collect()
}
