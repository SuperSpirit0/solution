import psycopg2
from flask import Flask
from config import host, user, password, db_name

app = Flask(__name__)

try:
    # conncet to database
    conn = psycopg2.connect(
        host=host,
        user=user,
        password=password,
        database=db_name
    )
    conn.autocommit = True

    with conn.cursor() as cursor:
        cursor.execute("""CREATE TABLE IF NOT EXISTS public.investors
(
    id serial NOT NULL,
    login text COLLATE pg_catalog."default",
    email text COLLATE pg_catalog."default",
    password character varying COLLATE pg_catalog."default" NOT NULL,
    jwt text COLLATE pg_catalog."default",
    country_code text COLLATE pg_catalog."default",
    is_public boolean,
    phone text COLLATE pg_catalog."default",
    image text COLLATE pg_catalog."default",
    CONSTRAINT investors_pkey PRIMARY KEY (id)
)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS public.friends
(
    user_id integer NOT NULL,
    friend_login text COLLATE pg_catalog."default" NOT NULL,
    added_at text COLLATE pg_catalog."default",
    id serial NOT NULL,
    CONSTRAINT friends_pkey PRIMARY KEY (id),
    CONSTRAINT friends_unique_key UNIQUE (user_id, friend_login)
)""")

        cursor.execute("""CREATE OR REPLACE FUNCTION make_uid() RETURNS text AS $$
DECLARE
    new_uid text;
    done bool;
BEGIN
    done := false;
    WHILE NOT done LOOP
        new_uid := md5(now()::text || random()::text);
        done := NOT EXISTS(SELECT 1 FROM posts WHERE id = new_uid);
    END LOOP;
    RETURN new_uid;
END;
$$ LANGUAGE PLPGSQL VOLATILE;""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS public.posts
(
    id character varying(100) COLLATE pg_catalog."default" NOT NULL DEFAULT make_uid(),
    content character varying(1000) COLLATE pg_catalog."default" NOT NULL,
    author text COLLATE pg_catalog."default" NOT NULL,
    tags character varying(20)[] COLLATE pg_catalog."default",
    created_at text COLLATE pg_catalog."default" NOT NULL,
    likes_count integer,
    dislikes_count integer,
    CONSTRAINT posts_pkey PRIMARY KEY (id)
)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS public.reactions
(
    id serial NOT NULL,
    user_id integer NOT NULL,
    reaction_type character varying COLLATE pg_catalog."default" NOT NULL,
    post_id character varying(1000) COLLATE pg_catalog."default",
    CONSTRAINT reactions_pkey PRIMARY KEY (id),
    CONSTRAINT react_unique_key UNIQUE (user_id, post_id)
)""")


except Exception as _ex:
    print("[INFO] Error while working with PostgreSQL", _ex)
