use rocket::http::{ContentType, Header, Status};
use rocket::local::blocking::Client;

use rocket_csrf::{CSRF_ERROR_HEADER, CSRF_ERROR_VALUE, XSRF_HEADER};

#[test]
fn form_submission_succeeds_with_valid_csrf_token() {
    let client = Client::tracked(super::rocket()).unwrap();
    let page = client.get("/").dispatch().into_string().unwrap();
    assert!(page.contains(r#"src="/static/csrf-client.js""#));
    let token = authenticity_token(&page);

    let response = client
        .post("/")
        .header(ContentType::Form)
        .body(format!("_authenticity_token={token}&message=Hello"))
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().unwrap(), "Accepted message: Hello");
}

#[test]
fn example_serves_the_client_module_imported_by_its_template() {
    let client = Client::tracked(super::rocket()).unwrap();
    let response = client.get("/static/csrf-client.js").dispatch();

    assert_eq!(response.status(), Status::Ok);
    assert!(response.into_string().unwrap().contains("createCsrfClient"));
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
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), None);
}

#[test]
fn api_submission_succeeds_with_xsrf_header() {
    let client = Client::tracked(super::rocket()).unwrap();
    let response = client.get("/api/bootstrap").dispatch();
    assert_eq!(response.headers().get_one("Cache-Control"), Some("no-store"));
    let token: String = response.into_json().expect("JSON XSRF token");

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
fn api_client_recovers_after_explicit_csrf_rejection() {
    let client = Client::tracked(super::rocket()).unwrap();
    let stale: String = client.get("/api/bootstrap").dispatch().into_json().unwrap();
    let body = r#"{"message":"Hello from test"}"#;

    let rejected = client.post("/api/message")
        .header(ContentType::JSON)
        .header(Header::new(XSRF_HEADER, "stale-token"))
        .body(body)
        .dispatch();
    assert_eq!(rejected.status(), Status::Forbidden);
    assert_eq!(rejected.headers().get_one(CSRF_ERROR_HEADER), Some(CSRF_ERROR_VALUE));

    let refreshed: String = client.get("/api/bootstrap").dispatch().into_json().unwrap();
    assert_ne!(stale, refreshed);
    let response = client.post("/api/message")
        .header(ContentType::JSON)
        .header(Header::new(XSRF_HEADER, refreshed))
        .body(body)
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
    assert_eq!(response.headers().get_one(CSRF_ERROR_HEADER), Some(CSRF_ERROR_VALUE));
}

fn authenticity_token(page: &str) -> &str {
    let prefix = r#"name="_authenticity_token" value=""#;
    let start = page.find(prefix).expect("csrf field") + prefix.len();
    let end = page[start..].find('"').expect("csrf value terminator") + start;
    &page[start..end]
}
