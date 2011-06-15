drop table if exists users;
create table users (
    username string not null,
    password_hash string not null
);

drop table if exists topic;
create table topic (
    topic_id integer primary key autoincrement,
    subject string not null
);

drop table if exists reply;
create table reply (
    topic_id integer not null,
    time integer not null,
    content string not null,
    author string not null
);

INSERT INTO users (username, password_hash) values ("tom", "$2a$12$1bH3kCP2gJT9hkQLLlp3G.IFMsr7jiRgoBLxsDXRzlDHN1qvcXQZu");

INSERT INTO topic (subject) values ("test post");
INSERT INTO reply (topic_id, time, content, author) values ("1", "123", "hello world", "tom");
INSERT INTO reply (topic_id, time, content, author) values ("1", "124", "hello again", "tom");

