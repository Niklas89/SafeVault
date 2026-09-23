-- SQLite schema used by the runnable sandbox (MySQL uses INT AUTO_INCREMENT).
CREATE TABLE IF NOT EXISTS Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL UNIQUE CHECK(length(Username) BETWEEN 3 AND 100),
    Email TEXT NOT NULL CHECK(length(Email) BETWEEN 3 AND 100)
);

-- Activity 2: existing Activity 1 users remain without login access.
-- Application startup adds this table without changing existing Users records.
CREATE TABLE IF NOT EXISTS Accounts (
    UserID INTEGER PRIMARY KEY REFERENCES Users(UserID),
    PasswordHash TEXT NOT NULL,
    Role TEXT NOT NULL CHECK(Role IN ('user', 'admin'))
);
