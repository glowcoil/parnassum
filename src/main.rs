#[macro_use]
extern crate rouille;
#[macro_use]
extern crate tera;
extern crate rusqlite;

use std::path::Path;
use std::sync::Mutex;

use rouille::{Request, Response};
use tera::Context;
use rusqlite::{Connection, NO_PARAMS};

fn main() {
    let mut tera = compile_templates!("src/template/**/*");

    let db = Mutex::new(Connection::open(Path::new("parnassum.db")).unwrap());

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
                let db = db.lock().unwrap();

                let mut stmt = db.prepare("SELECT name FROM users").unwrap();
                let mut rows = stmt.query_map(NO_PARAMS, |row| row.get(0)).unwrap();
                let mut values: Vec<String> = Vec::new();
                for row in rows {
                    values.push(row.unwrap());
                }

                let mut context = Context::new();
                context.insert("a", &values);
                Response::html(tera.render("index.html", &context).unwrap())
            },

            _ => {
                let mut context = Context::new();
                let mut response = Response::html(tera.render("404.html", &context).unwrap());
                response.status_code = 404;
                response
            },
        }
    });
}
