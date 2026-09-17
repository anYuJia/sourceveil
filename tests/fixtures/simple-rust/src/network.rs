use crate::auth::Session;

pub(crate) const DEFAULT_PORT: u16 = 8443;
pub(crate) static PROTOCOL_TAG: &str = "sv/1";

pub(crate) enum Transport {
    Plain,
    Tls { port: u16 },
}

pub(crate) fn describe(session: &Session) -> String {
    let transport = pick_transport();
    format!("{} via {} on {}", session.label(), transport_name(&transport), DEFAULT_PORT)
}

fn pick_transport() -> Transport {
    if DEFAULT_PORT == 0 {
        Transport::Plain
    } else {
        Transport::Tls { port: DEFAULT_PORT }
    }
}

fn transport_name(transport: &Transport) -> &'static str {
    match transport {
        Transport::Plain => PROTOCOL_TAG,
        Transport::Tls { port } => {
            if *port == DEFAULT_PORT {
                "tls"
            } else {
                "tls-alt"
            }
        }
    }
}
