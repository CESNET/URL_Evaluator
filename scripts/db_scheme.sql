create table sessions
(
    session_hash TEXT
        primary key,
    session      TEXT,
    idea_id      TEXT
);

create table sources
(
    id     INTEGER
        constraint sources_pk
            primary key autoincrement,
    source TEXT
);

create unique index sources_source_uindex
    on sources (source);

create table url_source
(
    id      INTEGER
        primary key autoincrement,
    url     TEXT,
    source  TEXT default -1,
    src_url TEXT default '',
    constraint unq
        unique (url, source, src_url)
);

create table urls
(
    url                   TEXT
        primary key,
    first_seen            date,
    last_seen             date,
    src                   TEXT,
    hash                  TEXT,
    classification        TEXT,
    classification_reason TEXT,
    note                  TEXT,
    reported              TEXT,
    url_occurrences       INTEGER,
    vt_stats              TEXT,
    evaluated             TEXT,
    file_mime_type        TEXT,
    content_size          INTEGER,
    threat_label          TEXT,
    status                TEXT,
    last_active           date,
    status_changed        TEXT default 'no',
    last_edit             TEXT default "",
    check (classification IN ('malicious', 'harmless', 'unreachable', 'unclassified', 'invalid', 'miner')),
    check (evaluated IN ('yes', 'no')),
    check (reported IN ('yes', 'no'))
);

create table url_session
(
    id      INTEGER
        primary key autoincrement,
    url     TEXT
        references urls,
    session TEXT
        references sessions
);

create unique index idx_url_session_unique
    on url_session (url, session);

