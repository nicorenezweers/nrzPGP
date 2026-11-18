//! Routen der Oberflaeche (nur fuer angemeldete Nutzer; sonst zeigt `App` die Anmeldung).

use crate::components::layout::Shell;
use crate::pages::*;
use dioxus::prelude::*;

#[derive(Routable, Clone, PartialEq, Debug)]
#[rustfmt::skip]
#[allow(clippy::enum_variant_names)]
pub enum Route {
    #[layout(Shell)]
        #[route("/")]
        Home {},
        #[route("/profiles/new")]
        NewProfile {},
        #[route("/profiles/import")]
        ImportProfilePage {},
        #[route("/profiles/:id")]
        ProfilePage { id: i64 },
        #[route("/profiles/:id/vault")]
        VaultPage { id: i64 },
        #[route("/encrypt")]
        Encrypt {},
        #[route("/decrypt")]
        Decrypt {},
        #[route("/sign")]
        Sign {},
        #[route("/verify")]
        Verify {},
        #[route("/contacts")]
        Contacts {},
        #[route("/contacts/:id")]
        ContactPage { id: i64 },
        #[route("/log")]
        Log {},
        #[route("/settings")]
        Settings {},
        #[route("/login")]
        LoginDone {},
        #[route("/:..segments")]
        NotFound { segments: Vec<String> },
}
