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
use rusqlite::{Connection, NO_PARAMS};

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
                    return error_register(&tera, "username is empty");
                }
                if input.password.is_empty() || input.confirm_password.is_empty() {
                    return error_register(&tera, "password is empty");
                }
                if input.confirm_password != input.password {
                    return error_register(&tera, "passwords do not match");
                }
                {
                    use rusqlite::OptionalExtension;
                    let db = db.lock().unwrap();
                    let existing: Option<String> = db.query_row("SELECT name FROM users WHERE name=(?)", &[&input.username], |row| row.get(0)).optional().unwrap();
                    if existing.is_some() {
                        return error_register(&tera, "username already exists");
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

fn error_register(tera: &tera::Tera, message: &str) -> Response {
    let mut context = Context::new();
    context.insert("message", message);
    Response::html(tera.render("register.html", &context).unwrap())
}
