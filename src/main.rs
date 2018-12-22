mod password;

#[macro_use]
extern crate rouille;
#[macro_use]
extern crate tera;
extern crate rusqlite;
extern crate ring;
extern crate base64;

use std::path::Path;
use std::sync::Mutex;

use rouille::{Request, Response};
use tera::Context;
use rusqlite::{Connection, NO_PARAMS, OptionalExtension};

use ring::rand::SecureRandom;

fn main() {
    let mut tera = compile_templates!("src/template/**/*");
    let db = Mutex::new(Connection::open(Path::new("parnassum.db")).unwrap());
    let mut rand = ring::rand::SystemRandom::new();

    rouille::start_server("0.0.0.0:80", move |request| {
        /* serve static files from static/ */
        if let Some(request) = request.remove_prefix("/static") {
            let response = rouille::match_assets(&request, "static");
            if response.is_success() {
                return response;
            }
        }

        router! { request,
            (GET) (/) => {
                let values = {
                    let db = db.lock().unwrap();

                    let mut stmt = db.prepare("SELECT name, text FROM worklogs INNER JOIN users ON worklogs.user_id = users.id").unwrap();
                    let mut rows = stmt.query_map(NO_PARAMS, |row| (row.get(0), row.get(1))).unwrap();
                    let mut values: Vec<(String, String)> = Vec::new();
                    for row in rows {
                        values.push(row.unwrap());
                    }
                    values
                };

                let mut context = Context::new();
                context.insert("a", &values);
                Response::html(tera.render("index.html", &context).unwrap())
            },

            (GET) (/register) => {
                Response::html(tera.render("register.html", &Context::new()).unwrap())
            },

            (POST) (/register) => {
                let input = post_input!(request, {
                    username: String,
                    password: String,
                    confirm_password: String,
                });

                if input.is_err() {
                    return error(&tera, "400 bad request", 400);
                }
                let input = input.unwrap();

                if input.username.is_empty() {
                    return error_message(&tera, "register.html", "username is empty");
                }
                if input.password.is_empty() || input.confirm_password.is_empty() {
                    return error_message(&tera, "register.html", "password is empty");
                }
                if input.confirm_password != input.password {
                    return error_message(&tera, "register.html", "passwords do not match");
                }
                {
                    let db = db.lock().unwrap();
                    let existing: Option<String> = db.query_row(
                        "SELECT name FROM users WHERE name=(?)", &[&input.username],
                        |row| row.get(0)).optional().unwrap();
                    if existing.is_some() {
                        return error_message(&tera, "register.html", "username already exists");
                    }

                    let mut salt = [0u8; 16];
                    rand.fill(&mut salt);
                    let mut hashed = [0u8; password::CREDENTIAL_LEN];
                    password::hash_password(&input.password, &salt, &mut hashed);
                    let mut stmt = db.prepare("INSERT INTO users (name, password, salt, created) VALUES ((?), (?), (?), datetime('now'))").unwrap();
                    stmt.execute(&[&input.username, &base64::encode(&hashed), &base64::encode(&salt)]).unwrap();
                }

                Response::html(tera.render("register.html", &Context::new()).unwrap())
            },

            (GET) (/login) => {
                Response::html(tera.render("login.html", &Context::new()).unwrap())
            },

            (POST) (/login) => {
                let input = post_input!(request, {
                    username: String,
                    password: String,
                });

                if input.is_err() {
                    return error(&tera, "400 bad request", 400);
                }
                let input = input.unwrap();

                if input.username.is_empty() {
                    return error_message(&tera, "login.html", "username is empty");
                }
                if input.password.is_empty() {
                    return error_message(&tera, "login.html", "password is empty");
                }
                {
                    let db = db.lock().unwrap();
                    let user: Option<(String, String)> = db.query_row(
                        "SELECT password, salt FROM users WHERE name = (?)",
                        &[&input.username],
                        |row| (row.get(0), row.get(1))).optional().unwrap();

                    if user.is_none() {
                        return error_message(&tera, "login.html", "user not found");
                    }
                    let (password, salt) = user.unwrap();

                    error_message(&tera, "login.html", &password::verify_password(&input.password, &base64::decode(&salt).unwrap(), &base64::decode(&password).unwrap()).to_string())
                }
            },

            _ => {
                return error(&tera, "404", 404);
            },
        }
    });
}

fn error(tera: &tera::Tera, error: &str, status_code: u16) -> Response {
    let mut context = Context::new();
    context.insert("error", error);
    Response::html(tera.render("error.html", &context).unwrap())
        .with_status_code(status_code)
}

fn error_message(tera: &tera::Tera, template: &str, message: &str) -> Response {
    let mut context = Context::new();
    context.insert("message", message);
    Response::html(tera.render(template, &context).unwrap())
}
