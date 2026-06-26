use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;

use rocket_csrf::{XSRF_COOKIE, XSRF_HEADER};

#[test]
fn form_submission_succeeds_with_valid_csrf_token() {
    let client = Client::tracked(super::rocket()).unwrap();
    let page = client.get("/").dispatch().into_string().unwrap();
    let token = authenticity_token(&page);

    let response = client
        .post("/")
        .header(ContentType::Form)
        .body(format!("_authenticity_token={token}&message=Hello"))
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "<p>Accepted message: Hello</p>");
}

#[test]
fn form_submission_rejects_invalid_csrf_token() {
    let client = Client::tracked(super::rocket()).unwrap();
    client.get("/").dispatch();

    let response = client
        .post("/")
        .header(ContentType::Form)
        .body("_authenticity_token=bogus&message=Hello")
        .dispatch();

    assert_eq!(response.status(), Status::Forbidden);
}

#[test]
fn api_submission_succeeds_with_xsrf_header() {
    let client = Client::tracked(super::rocket()).unwrap();
    let response = client.get("/api/bootstrap").dispatch();
    let token = response
        .cookies()
        .get(XSRF_COOKIE)
        .expect("xsrf cookie")
        .value()
        .to_string();

    let response = client
        .post("/api/message")
        .header(ContentType::JSON)
        .header(Header::new(XSRF_HEADER, token))
        .body(r#"{"message":"Hello from test"}"#)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "accepted api message: Hello from test");
}

#[test]
fn api_submission_rejects_missing_xsrf_header() {
    let client = Client::tracked(super::rocket()).unwrap();
    client.get("/api/bootstrap").dispatch();

    let response = client
        .post("/api/message")
        .header(ContentType::JSON)
        .body(r#"{"message":"Hello from test"}"#)
        .dispatch();

    assert_eq!(response.status(), Status::Forbidden);
}

fn authenticity_token(page: &str) -> &str {
    let prefix = r#"name="_authenticity_token" value=""#;
    let start = page.find(prefix).expect("csrf field") + prefix.len();
    let end = page[start..].find('"').expect("csrf value terminator") + start;
    &page[start..end]
}
