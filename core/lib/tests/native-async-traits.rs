//! Regression coverage for native guard futures and their lifetime/Send bounds.

use std::convert::Infallible;
use std::rc::Rc;

use rocket::data::{self, Data, FromData};
use rocket::form::{self, DataField, FromForm, FromFormField};
use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;
use rocket::request::{self, FromRequest, Request};
use rocket::{get, post, routes};

struct User<'r>(&'r str);

impl<'r> FromRequest<'r> for User<'r> {
    type Error = Infallible;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        rocket::tokio::task::yield_now().await;
        match req.headers().get_one("X-User") {
            Some(user) => request::Outcome::Success(User(user)),
            None => request::Outcome::Forward(Status::Unauthorized),
        }
    }
}

struct Body<'r>(&'r str);

impl<'r> FromData<'r> for Body<'r> {
    type Error = std::io::Error;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        let body = <&'r str as FromData<'r>>::from_data(req, data).await;
        rocket::tokio::task::yield_now().await;
        body.map(Body)
    }
}

struct Field<'r>(&'r str);

impl<'r> FromFormField<'r> for Field<'r> {
    async fn from_data(field: DataField<'r, '_>) -> form::Result<'r, Self> {
        let body = field.data.open(64.into()).into_string().await?;
        let body = rocket::request::local_cache!(field.request, body.into_inner());
        rocket::tokio::task::yield_now().await;
        Ok(Field(body))
    }
}

#[derive(FromForm)]
struct Fields<'r> {
    field: Field<'r>,
}

// A Send future need not produce a Send output. Do not accidentally strengthen
// FromRequest or FromData with a Send bound on Self during the migration.
struct Local(Rc<()>);

impl<'r> FromRequest<'r> for Local {
    type Error = Infallible;

    async fn from_request(_: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        rocket::tokio::task::yield_now().await;
        request::Outcome::Success(Local(Rc::new(())))
    }
}

impl<'r> FromData<'r> for Local {
    type Error = Infallible;

    async fn from_data(_: &'r Request<'_>, _: Data<'r>) -> data::Outcome<'r, Self> {
        rocket::tokio::task::yield_now().await;
        data::Outcome::Success(Local(Rc::new(())))
    }
}

fn assert_send(_: impl Send) { }

fn request_futures_are_send<'r, T: FromRequest<'r>>(req: &'r Request<'_>) {
    assert_send(T::from_request(req));
    assert_send(<Option<T>>::from_request(req));
    assert_send(<Result<T, T::Error>>::from_request(req));
    assert_send(<request::Outcome<T, T::Error>>::from_request(req));
    assert_send(req.guard::<T>());
}

fn data_future_is_send<'r, T: FromData<'r>>(req: &'r Request<'_>, data: Data<'r>) {
    assert_send(T::from_data(req, data));
}

fn form_futures_are_send<'r, T: FromForm<'r>>(
    ctxt: &mut T::Context,
    field: DataField<'r, '_>,
) {
    assert_send(T::push_data(ctxt, field));
}

fn field_future_is_send<'r, T: FromFormField<'r>>(field: DataField<'r, '_>) {
    assert_send(T::from_data(field));
}

#[post("/", data = "<body>")]
async fn submit<'r>(user: User<'r>, body: Body<'r>) -> String {
    rocket::tokio::task::yield_now().await;
    format!("{}:{}", user.0, body.0)
}

#[post("/form", data = "<fields>")]
fn submit_form(fields: form::Form<Fields<'_>>) -> String {
    fields.field.0.to_owned()
}

#[get("/local")]
fn local(value: Local) -> &'static str {
    assert_eq!(Rc::strong_count(&value.0), 1);
    "ok"
}

#[test]
fn borrowed_guards_and_native_form_derivation() {
    // Referencing these generic checks ensures the public trait contracts, not
    // just the concrete implementations, guarantee Send futures.
    let _ = request_futures_are_send::<Local>;
    let _ = data_future_is_send::<Local>;
    let _ = form_futures_are_send::<Fields<'_>>;
    let _ = field_future_is_send::<Field<'_>>;

    let client = Client::debug_with(routes![submit, submit_form, local]).unwrap();
    let response = client.post("/")
        .header(Header::new("X-User", "alice"))
        .body("hello")
        .dispatch();
    assert_eq!(response.into_string().as_deref(), Some("alice:hello"));

    let response = client.post("/").body("hello").dispatch();
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(client.get("/local").dispatch().into_string().as_deref(), Some("ok"));

    let body = concat!(
        "--BOUNDARY\r\n",
        "Content-Disposition: form-data; name=\"field\"; filename=\"value.txt\"\r\n",
        "Content-Type: text/plain\r\n\r\n",
        "hello form\r\n",
        "--BOUNDARY--\r\n",
    );
    let content_type = ContentType::parse_flexible("multipart/form-data; boundary=BOUNDARY")
        .expect("valid multipart content type");
    let response = client.post("/form").header(content_type).body(body).dispatch();
    assert_eq!(response.into_string().as_deref(), Some("hello form"));
}
