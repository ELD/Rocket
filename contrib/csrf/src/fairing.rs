use rocket::{Build, Rocket};
use rocket::fairing::{self, AdHoc, Fairing};
use rocket::figment::providers::Serialized;

use crate::{Config, CsrfState};

pub(crate) fn fairing() -> impl Fairing {
    AdHoc::try_on_ignite("CSRF Protection", |rocket| async move {
        let config = rocket.figment()
            .clone()
            .join(Serialized::default("csrf", Config::default()))
            .extract_inner::<Config>("csrf");

        match config {
            Ok(config) if !config.enable => Ok(rocket),
            Ok(config) => attach(rocket, config),
            Err(e) => {
                error!("invalid csrf configuration: {e}");
                Err(rocket)
            }
        }
    })
}

fn attach(rocket: Rocket<Build>, config: Config) -> fairing::Result {
    match config.validate() {
        Ok(()) => Ok(rocket.manage(CsrfState::new(config))),
        Err(message) => {
            error!("invalid csrf configuration: {message}");
            Err(rocket)
        }
    }
}
