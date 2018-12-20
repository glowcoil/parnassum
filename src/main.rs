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
    });
}
