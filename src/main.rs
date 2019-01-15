mod password;

#[macro_use]
extern crate rouille;
#[macro_use]
extern crate tera;
extern crate rusqlite;
extern crate ring;
extern crate base64;
extern crate serde_derive;
extern crate image;

use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use rouille::{Request, Response};
use rouille::input::post::BufferedFile;
use tera::Context;
use rusqlite::{Connection, NO_PARAMS, OptionalExtension};
use rusqlite::types::ToSql;
use ring::rand::SecureRandom;
use serde_derive::Serialize;
use image::png::PNGDecoder;
use image::ImageDecoder;

#[derive(Serialize)]
struct User {
    id: u32,
    name: String,
    icon: String,
    token: String,
}

#[derive(Serialize)]
struct Worklog {
    user: Profile,
    text: String,
    link: Option<String>,
}

#[derive(Serialize)]
struct Profile {
    id: u32,
    name: String,
    icon: String,
    created: String,
}

#[derive(Serialize)]
struct LeaderboardEntry {
    user: Profile,
    streak: u32,
    current: bool,
}

struct App {
    tera: tera::Tera,
    db: Mutex<Connection>,
    rand: ring::rand::SystemRandom,
}

impl App {
    fn new() -> App {
        App {
            tera: compile_templates!("src/template/**/*"),
            db: Mutex::new(Connection::open(Path::new("parnassum.db")).unwrap()),
            rand: ring::rand::SystemRandom::new(),
        }
    }

    fn handle_request(&self, request: &Request) -> Result<Response, Box<dyn Error>> {
        router! { request,
            (GET) (/) => {
                let mut context = Context::new();
                if let Some(user) = self.verify_session(&request)? {
                    context.insert("user", &user);
                }

                let leaderboard = {
                    let db = self.db.lock().unwrap();

                    let mut stmt = db.prepare("
                    SELECT users.id,
                           users.name,
                           IFNULL(users.icon, 'default.png'),
                           users.created,
                           1 + CAST(julianday() / 7 AS INTEGER) -
                               (SELECT MAX(CAST(julianday(worklogs.created) / 7 AS INTEGER))
                                FROM worklogs
                                WHERE worklogs.user_id = users.id
                                AND (SELECT count(*)
                                     FROM worklogs w2
                                     WHERE w2.user_id = users.id AND
                                           CAST(julianday(worklogs.created) / 7 AS INTEGER) - 1
                                           = CAST(julianday(w2.created) / 7 AS INTEGER))
                                    = 0)
                           AS streak,
                           (SELECT count(*)
                               FROM worklogs
                               WHERE worklogs.user_id = users.id AND
                                     CAST(julianday(worklogs.created) / 7 AS INTEGER)
                                     = CAST(julianday() / 7 AS INTEGER))
                              > 0 AS this_week,
                           (SELECT count(*)
                               FROM worklogs
                               WHERE worklogs.user_id = users.id AND
                                     CAST(julianday(worklogs.created) / 7 AS INTEGER)
                                     = CAST(julianday() / 7 AS INTEGER) - 1)
                              > 0 AS last_week
                    FROM users
                    WHERE this_week OR last_week
                    ORDER BY this_week DESC, streak DESC").unwrap();
                    let mut rows = stmt.query_map(NO_PARAMS, |row| {
                        let current: bool = row.get(5);
                        let streak: u32 = row.get(4);
                        LeaderboardEntry {
                            user: Profile { id: row.get(0), name: row.get(1), icon: row.get(2), created: row.get(3) },
                            streak: if current { streak } else { streak - 1 },
                            current: current,
                        }
                    })?;
                    let mut leaderboard: Vec<LeaderboardEntry> = Vec::new();
                    for row in rows {
                        leaderboard.push(row?);
                    }
                    leaderboard
                };

                let worklogs = {
                    let db = self.db.lock().unwrap();

                    let mut stmt = db.prepare("SELECT users.id, users.name, IFNULL(users.icon, 'default.png'), date(users.created), text, link FROM worklogs INNER JOIN users ON worklogs.user_id = users.id ORDER BY worklogs.created DESC").unwrap();
                    let mut rows = stmt.query_map(NO_PARAMS, |row|
                        Worklog {
                            user: Profile { id: row.get(0), name: row.get(1), icon: row.get(2), created: row.get(3) },
                            text: row.get(4),
                            link: row.get(5),
                        }).unwrap();
                    let mut worklogs: Vec<Worklog> = Vec::new();
                    for row in rows {
                        worklogs.push(row?);
                    }
                    worklogs
                };

                context.insert("leaderboard", &leaderboard);
                context.insert("worklogs", &worklogs);
                Ok(Response::html(self.tera.render("index.html", &context)?))
            },

            (GET) (/user/{name: String}) => {
                let mut context = Context::new();
                if let Some(user) = self.verify_session(&request)? {
                    context.insert("user", &user);
                }

                {
                    let db = self.db.lock().unwrap();
                    let profile: Option<Profile> = db.query_row(
                        "SELECT id, name, IFNULL(users.icon, 'default.png'), date(created) FROM users WHERE name = (?)", &[&name],
                        |row| Profile { id: row.get(0), name: row.get(1), icon: row.get(2), created: row.get(3) }).optional()?;
                    if let Some(profile) = profile {
                        context.insert("profile", &profile);
                    } else {
                        return Ok(self.error("user not found", 404));
                    }
                }

                Ok(Response::html(self.tera.render("profile.html", &context).unwrap()))
            },

            (GET) (/worklog/post) => {
                let mut context = Context::new();
                if let Some(user) = self.verify_session(&request)? {
                    context.insert("user", &user);
                } else {
                    return Ok(Response::redirect_303("/"));
                }

                Ok(Response::html(self.tera.render("post.html", &context).unwrap()))
            },

            (POST) (/worklog/post) => {
                let user = self.verify_session(&request)?;

                if user.is_none() {
                    return Ok(Response::redirect_303("/"));
                }
                let user = user.unwrap();

                let input = post_input!(request, {
                    worklog: String,
                    link: String,
                });

                if input.is_err() {
                    return Ok(self.error("400 bad request", 400));
                }
                let input = input.unwrap();

                if input.worklog.is_empty() {
                    return Ok(self.error_message("post.html", "worklog is empty"));
                }

                let link = if input.link.is_empty() {
                    None
                } else {
                    Some(input.link)
                };

                let db = self.db.lock().unwrap();
                let mut stmt = db.prepare("INSERT INTO worklogs (user_id, text, link, created) VALUES ((?), (?), (?), datetime('now'))").unwrap();
                stmt.execute(&[&user.id as &ToSql, &input.worklog, &link])?;

                Ok(Response::redirect_303("/"))
            },

            (GET) (/register) => {
                if self.verify_session(&request)?.is_some() {
                    return Ok(Response::redirect_303("/"));
                }
                Ok(Response::html(self.tera.render("register.html", &Context::new()).unwrap()))
            },

            (POST) (/register) => {
                if self.verify_session(&request)?.is_some() {
                    return Ok(Response::redirect_303("/"));
                }

                let input = post_input!(request, {
                    username: String,
                    password: String,
                    confirm_password: String,
                    remember: bool,
                });

                if input.is_err() {
                    return Ok(self.error("400 bad request", 400));
                }
                let input = input.unwrap();

                if input.username.is_empty() {
                    return Ok(self.error_message("register.html", "username is empty"));
                }
                if input.password.is_empty() || input.confirm_password.is_empty() {
                    return Ok(self.error_message("register.html", "password is empty"));
                }
                if input.confirm_password != input.password {
                    return Ok(self.error_message("register.html", "passwords do not match"));
                }

                let db = self.db.lock().unwrap();
                let existing: Option<String> = db.query_row(
                    "SELECT name FROM users WHERE name=(?)", &[&input.username],
                    |row| row.get(0)).optional()?;
                if existing.is_some() {
                    return Ok(self.error_message("register.html", "username already exists"));
                }

                /* create user */

                let mut salt = [0u8; 16];
                self.rand.fill(&mut salt)?;
                let mut hashed = [0u8; password::CREDENTIAL_LEN];
                password::hash_password(&input.password, &salt, &mut hashed);
                let mut stmt = db.prepare("INSERT INTO users (name, password, salt, created) VALUES ((?), (?), (?), datetime('now'))")?;
                stmt.execute(&[&input.username, &base64::encode(&hashed), &base64::encode(&salt)])?;

                /* get user id */

                let id: u32 = db.query_row(
                    "SELECT id, password, salt FROM users WHERE name = (?)",
                    &[&input.username],
                    |row| row.get(0))?;

                /* log in */

                let mut token = [0u8; 32];
                self.rand.fill(&mut token)?;
                let token_base64 = base64::encode(&token);

                let mut stmt = db.prepare("INSERT INTO sessions (user_id, token, created) VALUES ((?), (?), datetime('now'))")?;
                stmt.execute(&[&id as &ToSql, &token_base64])?;

                if input.remember {
                    Ok(Response::redirect_303("/").with_additional_header("Set-Cookie", format!("session={}; Max-Age=2147483648; Path=/;", &token_base64)))
                } else {
                    Ok(Response::redirect_303("/").with_additional_header("Set-Cookie", format!("session={}; Path=/;", &token_base64)))
                }
            },

            (GET) (/login) => {
                if self.verify_session(&request)?.is_some() {
                    return Ok(Response::redirect_303("/"));
                }

                Ok(Response::html(self.tera.render("login.html", &Context::new()).unwrap()))
            },

            (POST) (/login) => {
                if self.verify_session(&request)?.is_some() {
                    return Ok(Response::redirect_303("/"));
                }

                let input = post_input!(request, {
                    username: String,
                    password: String,
                    remember: bool,
                });

                if input.is_err() {
                    return Ok(self.error("400 bad request", 400));
                }
                let input = input.unwrap();

                if input.username.is_empty() {
                    return Ok(self.error_message("login.html", "username is empty"));
                }
                if input.password.is_empty() {
                    return Ok(self.error_message("login.html", "password is empty"));
                }
                {
                    let user: Option<(u32, String, String)> = {
                        let db = self.db.lock().unwrap();
                        db.query_row(
                            "SELECT id, password, salt FROM users WHERE name = (?)",
                            &[&input.username],
                            |row| (row.get(0), row.get(1), row.get(2))).optional()?
                    };

                    if user.is_none() {
                        return Ok(self.error_message("login.html", "user not found"));
                    }
                    let (id, password, salt) = user.unwrap();

                    if password::verify_password(&input.password, &base64::decode(&salt)?, &base64::decode(&password)?) {
                        let mut token = [0u8; 32];
                        self.rand.fill(&mut token)?;
                        let token_base64 = base64::encode(&token);

                        {
                            let db = self.db.lock().unwrap();
                            let mut stmt = db.prepare("INSERT INTO sessions (user_id, token, created) VALUES ((?), (?), datetime('now'))")?;
                            stmt.execute(&[&id as &ToSql, &token_base64])?;
                        }

                        if input.remember {
                            Ok(Response::redirect_303("/").with_additional_header("Set-Cookie", format!("session={}; Max-Age=2147483648; Path=/;", &token_base64)))
                        } else {
                            Ok(Response::redirect_303("/").with_additional_header("Set-Cookie", format!("session={}; Path=/;", &token_base64)))
                        }
                    } else {
                        Ok(self.error_message("login.html", "incorrect password"))
                    }
                }
            },

            (POST) (/logout) => {
                if let Some(user) = self.verify_session(&request)? {
                    let db = self.db.lock().unwrap();
                    let mut stmt = db.prepare("DELETE FROM sessions WHERE token = (?)")?;
                    stmt.execute(&[&user.token])?;
                }
                Ok(Response::redirect_303("/").with_additional_header("Set-Cookie", "session=; Max-Age=0;"))
            },

            (GET) (/settings) => {
                let mut context = Context::new();
                if let Some(user) = self.verify_session(&request)? {
                    context.insert("user", &user);
                } else {
                    return Ok(Response::redirect_303("/"));
                }

                Ok(Response::html(self.tera.render("settings.html", &context).unwrap()))
            },

            (POST) (/settings/username) => {
                let user = self.verify_session(&request)?;
                if user.is_none() {
                    return Ok(Response::redirect_303("/"));
                }
                let user = user.unwrap();

                let mut context = Context::new();
                context.insert("user", &user);

                let input = post_input!(request, {
                    username: String,
                });

                if input.is_err() {
                    return Ok(self.error("400 bad request", 400));
                }
                let input = input.unwrap();

                if input.username.is_empty() {
                    context.insert("message", "username is empty");
                    return Ok(Response::html(self.tera.render("settings.html", &context).unwrap()));
                }

                {
                    let db = self.db.lock().unwrap();

                    let existing: Option<String> = db.query_row(
                        "SELECT name FROM users WHERE name = (?) AND id != (?)", &[&input.username as &ToSql, &user.id],
                        |row| row.get(0)).optional()?;
                    if existing.is_some() {
                        context.insert("message", "username already exists");
                        return Ok(Response::html(self.tera.render("settings.html", &context).unwrap()));
                    }

                    let mut stmt = db.prepare("UPDATE users SET name = (?) WHERE id = (?)")?;
                    stmt.execute(&[&input.username as &ToSql, &user.id])?;
                }

                Ok(Response::redirect_303("/settings"))
            },

            (POST) (/settings/password) => {
                let user = self.verify_session(&request)?;
                if user.is_none() {
                    return Ok(Response::redirect_303("/"));
                }
                let user = user.unwrap();

                let mut context = Context::new();
                context.insert("user", &user);

                let input = post_input!(request, {
                    password: String,
                    confirm_password: String,
                });

                if input.is_err() {
                    return Ok(self.error("400 bad request", 400));
                }
                let input = input.unwrap();

                if input.password.is_empty() || input.confirm_password.is_empty() {
                    context.insert("message", "password is empty");
                    return Ok(Response::html(self.tera.render("settings.html", &context).unwrap()));
                }
                if input.confirm_password != input.password {
                    context.insert("message", "passwords do not match");
                    return Ok(Response::html(self.tera.render("settings.html", &context).unwrap()));
                }

                {
                    let db = self.db.lock().unwrap();

                    let salt: String = db.query_row(
                        "SELECT salt FROM users WHERE id = (?)", &[&user.id],
                        |row| row.get(0))?;
                    let salt = base64::decode(&salt)?;
                    let mut hashed = [0u8; password::CREDENTIAL_LEN];
                    password::hash_password(&input.password, &salt, &mut hashed);

                    let mut stmt = db.prepare("UPDATE users SET password = (?) WHERE id = (?)")?;
                    stmt.execute(&[&base64::encode(&hashed) as &ToSql, &user.id])?;
                }

                Ok(Response::redirect_303("/settings"))
            },

            (POST) (/settings/icon) => {
                let user = self.verify_session(&request)?;
                if user.is_none() {
                    return Ok(Response::redirect_303("/"));
                }
                let user = user.unwrap();

                let mut context = Context::new();
                context.insert("user", &user);

                let input = post_input!(request, {
                    icon: BufferedFile,
                });

                if input.is_err() {
                    return Ok(self.error("400 bad request", 400));
                }
                let input = input.unwrap();

                {
                    let mut buffer = PNGDecoder::new(&input.icon.data[..]);
                    if let Ok((width, height)) = buffer.dimensions() {
                        if width != 16 || height != 16 {
                            context.insert("message", "image must be 16x16");
                            return Ok(Response::html(self.tera.render("settings.html", &context).unwrap()));
                        }
                    } else {
                        context.insert("message", "invalid image");
                        return Ok(Response::html(self.tera.render("settings.html", &context).unwrap()));
                    }
                }

                let mut file = File::create(format!("static/icon/{}.png", &user.id.to_string()))?;
                file.write(&input.icon.data[..])?;

                {
                    let db = self.db.lock().unwrap();

                    let mut stmt = db.prepare("UPDATE users SET icon = (?) WHERE id = (?)")?;
                    stmt.execute(&[&format!("{}.png", &user.id.to_string()) as &ToSql, &user.id])?;
                }

                Ok(Response::redirect_303("/settings"))
            },

            _ => {
                return Ok(self.error("404", 404));
            },
        }
    }

    fn verify_session(&self, request: &Request) -> Result<Option<User>, Box<dyn Error>> {
        if let Some((_, token)) = rouille::input::cookies(request).find(|&(name, _)| name == "session") {
            let db = self.db.lock().unwrap();
            Ok(db.query_row(
                "SELECT users.id, users.name, IFNULL(users.icon, 'default.png') FROM sessions INNER JOIN users ON sessions.user_id = users.id WHERE token = (?)",
                &[&token],
                |row| User { id: row.get(0), name: row.get(1), icon: row.get(2), token: token.to_string() }).optional()?)
        } else {
            Ok(None)
        }
    }

    fn error(&self, error: &str, status_code: u16) -> Response {
        let mut context = Context::new();
        context.insert("error", error);
        Response::html(self.tera.render("error.html", &context).unwrap())
            .with_status_code(status_code)
    }

    fn error_message(&self, template: &str, message: &str) -> Response {
        let mut context = Context::new();
        context.insert("message", message);
        Response::html(self.tera.render(template, &context).unwrap())
    }
}

fn main() {
    let app = App::new();

    rouille::start_server("0.0.0.0:80", move |request| {
        /* serve static files from static/ */
        if let Some(request) = request.remove_prefix("/static") {
            let response = rouille::match_assets(&request, "static");
            if response.is_success() {
                return response;
            }
        }

        app.handle_request(request).unwrap()
    });
}
