#[macro_use]
extern crate rocket;

#[cfg(test)]
mod tests;

use rocket::form::FromForm;
use rocket::fs::{relative, FileServer};
use rocket::serde::{Deserialize, Serialize, json::Json};
use rocket_dyn_templates::{Template, context};

use rocket_csrf::{
    Csrf, CsrfForm, CsrfGuardError, CsrfToken, VerifiedXsrf, XsrfToken,
};

#[derive(FromForm)]
struct Message<'r> {
    message: &'r str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct ApiMessage<'r> {
    message: &'r str,
}

#[get("/")]
fn index(csrf: CsrfToken) -> Template {
    Template::render("index", context! { csrf })
}

#[post("/", data = "<form>")]
fn submit(form: CsrfForm<Message<'_>>) -> String {
    format!("Accepted message: {}", form.message)
}

#[get("/api/bootstrap")]
fn bootstrap(xsrf: XsrfToken) -> Json<XsrfToken> {
    Json(xsrf)
}

#[post("/api/message", format = "json", data = "<message>")]
fn api_message(
    xsrf: Result<VerifiedXsrf, CsrfGuardError>,
    message: Json<ApiMessage<'_>>,
) -> Result<String, CsrfGuardError> {
    xsrf?;
    Ok(format!("accepted api message: {}", message.message))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Csrf::fairing())
        .attach(Template::fairing())
        .mount("/", routes![index, submit, bootstrap, api_message])
        .mount("/static", FileServer::new(relative!("static")))
}
