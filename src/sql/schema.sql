CREATE TABLE "users" (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `name` TEXT NOT NULL UNIQUE,
    `password` TEXT NOT NULL,
    `salt` TEXT NOT NULL,
    `icon` TEXT,
    `created` TEXT
);

CREATE TABLE "worklogs" (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `user_id` INTEGER NOT NULL,
    `text` TEXT NOT NULL,
    `link` TEXT,
    `created` TEXT
);

CREATE TABLE "sessions" (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `user_id` INTEGER NOT NULL,
    `token` TEXT NOT NULL,
    `created` TEXT
);

CREATE UNIQUE INDEX `sessions_token` ON `sessions` ( `token` ASC );
