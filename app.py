#!/usr/bin/env python

"""
    flask-forum
    Copyright (C) 2011 Tom Dryer <tomdryer.com@gmail.com>
    License: 3-clause BSD
"""

#TODO: format reply text before writing it to the database
#TODO: add CSRF token to logout
#TODO: come up with a better SQL query for topics()

import sqlite3
from bcrypt import hashpw, gensalt
from string import ascii_uppercase, ascii_lowercase, digits
from datetime import datetime
from time import time
from flask import Flask, render_template, request, g, redirect, session, \
    abort, url_for, flash
from flaskext.wtf import Form, TextField, PasswordField, Required, EqualTo, \
    Length, ValidationError, TextAreaField
app = Flask(__name__)

DATABASE = "flask-forum.db"
app.secret_key = "development key"
MAX_USERNAME_LENGTH = 20

class RegistrationForm(Form):
    username = TextField("Username", validators=[Required(), \
            Length(max=MAX_USERNAME_LENGTH)])
    password1 = PasswordField("Password", validators=[Required()])
    password2 = PasswordField("Password (verify)", validators=[Required(), \
            EqualTo("password1", message="Passwords must match.")])

    def validate_username(form, field):
        # check if username is in use
        username = field.data
        existing = query_db("SELECT * FROM users WHERE username = ?", \
                [username], one=True)
        if existing != None:
            raise ValidationError("Sorry, this username is already taken.")

class LoginForm(Form):
    username = TextField("Username", validators=[Required(), \
            Length(max=MAX_USERNAME_LENGTH)])
    password = PasswordField("Password", validators=[Required()])

class ReplyForm(Form):
    content = TextAreaField("Reply", validators=[Required()])

class NewTopicForm(Form):
    subject = TextField("Subject", validators=[Required()])
    content = TextAreaField("Reply", validators=[Required()])

def format_datetime(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d @ %I:%M %p')

def format_elapsed_datetime(time):
    seconds = int(timestamp()) - int(time)
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    if days > 1:
        return "%i days ago" % days
    elif days == 1:
        return "1 day ago"
    elif hours > 1:
        return "%i hours ago" % hours
    elif hours == 1:
        return "1 hour ago"
    elif minutes > 1:
        return "%i minutes ago" % minutes
    elif minutes == 1:
        return "1 minute ago"
    elif seconds > 1:
        return "%i seconds ago" % seconds
    else:
        return "1 second ago"

def timestamp():
    return str(int(time()))

def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv

@app.before_request
def before_request():
    # connect database
    g.db = sqlite3.connect(DATABASE)
    # look up the current user
    g.username = None
    if "username" in session:
        g.username = query_db("SELECT * FROM users where username = ?", 
                [session["username"]], one=True)["username"]

@app.after_request
def after_request(response):
    g.db.close()
    return response

@app.route('/')
def topics():
    # get a list of topics sorted by the date of their last reply
    topics = query_db("SELECT * FROM topic ORDER BY (SELECT MAX(time) FROM \
            reply WHERE reply.topic_id = topic.topic_id) DESC")
    for topic in topics:
        # get number of replies to topic
        reply_count = query_db("SELECT count(*) FROM reply WHERE topic_id = ?", 
                [topic["topic_id"]], one=True)["count(*)"]
        topic["replies"] = reply_count - 1
        # get date of most recent reply
        last_reply = query_db("SELECT time FROM reply WHERE topic_id = ? ORDER \
                BY time DESC LIMIT 1", [topic["topic_id"]], one=True)["time"]
        topic["last_reply_date"] = last_reply
    return render_template("topics.html", topics=topics)

@app.route('/topic/new', methods=['GET', 'POST'])
def new_topic():
    form = NewTopicForm()
    if form.validate_on_submit():
        new_topic_id = post_topic(form.subject.data, form.content.data)
        flash("New topic posted.")
        return redirect('/topic/' + new_topic_id)
    return render_template("newtopic.html", form=form)

@app.route('/topic/<topic_id>', methods=['GET', 'POST'])
def view_topic(topic_id):
    # view or post to a topic
    subject = query_db("SELECT subject FROM topic WHERE topic_id = ?", 
            [topic_id], one=True)
    if subject is None:
        abort(404)
    subject = subject["subject"]
    
    form = ReplyForm()
    if form.validate_on_submit():
        # need to be logged in
        if not g.username:
            abort(403)
        post_reply(topic_id, form.content.data)
        flash("Reply posted.")
    
    replies = query_db("SELECT * FROM reply WHERE topic_id = ? ORDER BY time",
            [topic_id])
    return render_template("topic.html", subject=subject, replies=replies, 
                           form=form)

def post_topic(subject, content):
    g.db.execute("INSERT INTO topic (subject) values (?);", [subject])
    g.db.commit()
    topic_id = query_db("select last_insert_rowid()")[0]["last_insert_rowid()"]
    topic_id = str(topic_id)
    post_reply(topic_id, content)
    return topic_id

def post_reply(topic_id, content):
    g.db.execute("INSERT INTO reply (topic_id, time, content, author) values \
            (?, ?, ?, ?);", [topic_id, timestamp(), content, g.username])
    g.db.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # check if username/password is correct
        username = form.username.data
        password = form.password.data
        user = query_db("SELECT password_hash FROM users WHERE username = ?", \
                [username], one=True)
        if user != None:
            pw_hash = hashpw(password, user["password_hash"])
            if (pw_hash == user["password_hash"]):
                # login and redirect to topics
                session["username"] = username
                flash("Login successful.")
                return redirect("/")
        # flash an error
        flash("Invalid username or password.")
    return render_template("login.html", form=form)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop("username", None)
    g.username = None
    return render_template("template.html", page_name="Logout", 
            page_body="You have been logged out.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # create account
        username = form.username.data
        password = form.password1.data
        pw_hash = hashpw(password, gensalt())
        g.db.execute("INSERT INTO users (username, password_hash) \
                values (?, ?)", [username, pw_hash])
        g.db.commit()
        # redirect to login
        flash("Account created. Login to continue.")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['datetimeelapsedformat'] = format_elapsed_datetime

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

