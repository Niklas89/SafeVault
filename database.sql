-- SQLite schema used by the runnable sandbox (MySQL uses INT AUTO_INCREMENT).
CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL UNIQUE CHECK(length(Username) BETWEEN 3 AND 100),
    Email TEXT NOT NULL CHECK(length(Email) BETWEEN 3 AND 100)
);
