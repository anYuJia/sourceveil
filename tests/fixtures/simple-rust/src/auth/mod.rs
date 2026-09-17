mod token;

pub(crate) use token::Session;

pub(crate) fn establish_session(user: &str) -> Session {
    let token = token::mint(user);
    Session::new(user, token)
}
