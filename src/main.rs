mod password;

#[macro_use]
extern crate rouille;
#[macro_use]
extern crate tera;
extern crate rusqlite;
extern crate ring;
extern crate base64;
extern crate serde_derive;

use std::path::Path;
use std::sync::Mutex;

use rouille::{Request, Response};
use tera::Context;
use rusqlite::{Connection, NO_PARAMS, OptionalExtension};
use rusqlite::types::ToSql;
use ring::rand::SecureRandom;
use serde_derive::Serialize;

#[derive(Serialize)]
struct User {
    id: u32,
    name: String,
    token: String,
}

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
                let mut context = Context::new();
                if let Some(user) = verify_session(&db, &request) {
                    context.insert("user", &user);
                }

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

                context.insert("a", &values);
                Response::html(tera.render("index.html", &context).unwrap())
            },

            (GET) (/register) => {
                if verify_session(&db, &request).is_some() {
                    return Response::redirect_303("/");
                }
                Response::html(tera.render("register.html", &Context::new()).unwrap())
            },

            (POST) (/register) => {
                if verify_session(&db, &request).is_some() {
                    return Response::redirect_303("/");
                }

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

                    return Response::redirect_303("/login");
                }

                Response::html(tera.render("register.html", &Context::new()).unwrap())
            },

            (GET) (/login) => {
                if verify_session(&db, &request).is_some() {
                    return Response::redirect_303("/");
                }

                Response::html(tera.render("login.html", &Context::new()).unwrap())
            },

            (POST) (/login) => {
                if verify_session(&db, &request).is_some() {
                    return Response::redirect_303("/");
                }

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
                    let user: Option<(u32, String, String)> = {
                        let db = db.lock().unwrap();
                        db.query_row(
                            "SELECT id, password, salt FROM users WHERE name = (?)",
                            &[&input.username],
                            |row| (row.get(0), row.get(1), row.get(2))).optional().unwrap()
                    };

                    if user.is_none() {
                        return error_message(&tera, "login.html", "user not found");
                    }
                    let (id, password, salt) = user.unwrap();

                    if password::verify_password(&input.password, &base64::decode(&salt).unwrap(), &base64::decode(&password).unwrap()) {
                        let mut token = [0u8; 32];
                        rand.fill(&mut token);
                        let token_base64 = base64::encode(&token);

                        {
                            let db = db.lock().unwrap();
                            let mut stmt = db.prepare("INSERT INTO sessions (user_id, token, created) VALUES ((?), (?), datetime('now'))").unwrap();
                            stmt.execute(&[&id as &ToSql, &token_base64]).unwrap();
                        }

                        Response::redirect_303("/").with_additional_header("Set-Cookie", "session=".to_owned() + &token_base64)
                    } else {
                        error_message(&tera, "login.html", "incorrect password")
                    }
                }
            },

            (POST) (/logout) => {
                if let Some(user) = verify_session(&db, &request) {
                    let db = db.lock().unwrap();
                    let mut stmt = db.prepare("DELETE FROM sessions WHERE token = (?)").unwrap();
                    stmt.execute(&[&user.token]).unwrap();
                }
                Response::redirect_303("/").with_additional_header("Set-Cookie", "session=")
            },

            _ => {
                return error(&tera, "404", 404);
            },
        }
    });
}

fn verify_session(db: &Mutex<Connection>, request: &Request) -> Option<User> {
    if let Some((_, token)) = rouille::input::cookies(request).find(|&(name, _)| name == "session") {
        let db = db.lock().unwrap();
        db.query_row(
            "SELECT users.id, users.name FROM sessions INNER JOIN users ON sessions.user_id = users.id WHERE token = (?)",
            &[&token],
            |row| User { id: row.get(0), name: row.get(1), token: token.to_string() }).optional().unwrap()
    } else {
        None
    }
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
