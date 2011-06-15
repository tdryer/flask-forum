import sqlite3
from bcrypt import hashpw, gensalt
from random import choice
from string import ascii_uppercase, ascii_lowercase, digits
from datetime import datetime
from time import time
from flask import Flask, render_template, request, g, redirect, session, abort
app = Flask(__name__)

SECRET_KEY = "one two three four"
DATABASE = "flask-forum.db"

MAX_USERNAME_LENGTH = 20

#TODO: filter all input before adding to db
#TODO: allow some markup in replies
#TODO: refactoring /post

def format_datetime(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d @ %I:%M %p')

def format_elapsed_datetime(time):
    seconds = int(timestamp()) - int(time)
    #TODO: round up so 1.99 hours is not displayed as 1 hour?
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

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = ''.join(choice(ascii_uppercase + 
                digits) for x in range(16))
    return session["csrf_token"]

@app.before_request
def before_request():
    # CSRF protection
    if request.method == "POST":
        token = session.pop("csrf_token", None)
        if not token or token != request.form.get("csrf_token"):
            abort(403)
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
    # TODO: do this without a subquery?
    topics = query_db("SELECT * FROM topic ORDER BY (SELECT MAX(time) FROM \
            reply WHERE reply.topic_id = topic.topic_id) DESC")
    for topic in topics:
        # TODO: combine these queries into the main one
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
    message = None
    
    # view or submit the new topic form
    if request.method == "POST":
        if not g.username:
            abort(403)
        subject = request.form.get("subject")
        content = request.form.get("content")
        if not subject or not content:
            message = "All fields are required."
        else:
            new_topic_id = post_topic(subject, content)
            return redirect('/topic/' + new_topic_id)
    
    return render_template("newtopic.html", message=message)

@app.route('/topic/<topic_id>', methods=['GET', 'POST'])
def view_topic(topic_id):
    # view or post to a topic
    subject = query_db("SELECT subject FROM topic WHERE topic_id = ?", 
            [topic_id], one=True)
    if subject is None:
        abort(404)
    subject = subject["subject"]
    
    message = None
    
    if request.method == "POST":
        # post a reply to this topic
        if not g.username:
            abort(403)
        content = request.form.get("content")
        if not content:
            message = "Nothing to post!"
        else:
            post_reply(topic_id, content)
    
    replies = query_db("SELECT * FROM reply WHERE topic_id = ? ORDER BY time",
            [topic_id])
    return render_template("topic.html", subject=subject, replies=replies, 
                           message=message)

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
    message = None
    username = ""
    if request.method == "POST":
        # log in the user
        success = False
        username = request.form["username"]
        password = request.form["password"]
        user = query_db("SELECT * FROM users WHERE username = ?", [username], 
                one=True)
        if user != None:
            if hashpw(password, user["password_hash"]) == user["password_hash"]:
                success = True
        if success:
            session["username"] = username
            return redirect("/")
        else:
            message = "Incorrect username or password."
    # display login form
    return render_template("login.html", message=message, username=username)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop("username", None)
    g.username = None
    return render_template("template.html", page_name="Logout", 
            page_body="You have been logged out.")

def is_username_valid(username):
    if len(username) > MAX_USERNAME_LENGTH:
        return "Usernames > %i characters are not allowed." % \
                MAX_USERNAME_LENGTH
    for c in username:
        if c not in (ascii_lowercase + ascii_uppercase + digits):
            return "Usernames may only contain alphanumeric characters."
    existing = query_db("SELECT * FROM users WHERE username = ?", [username], 
            one=True)
    if existing != None:
        return "That username is already taken."
    return True

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        # create new account
        
        error = None
        
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        if not username or not password1 or not password2:
            error = "All fields are required."
        
        if not error:
            if password1 != password2:
                error = "Passwords do not match."
        
        if not error:
                res = is_username_valid(username)
                if res != True:
                    error = res
        
        if not error:
            error = "Your account has been created."
            pw_hash = hashpw(password1, gensalt())
            g.db.execute("INSERT INTO users (username, password_hash)" + 
                    " values (?, ?)", [username, pw_hash])
            g.db.commit()
        
        return render_template("register.html", message=error,
                max_len=MAX_USERNAME_LENGTH, username=username)
    else:
        # show login form
        return render_template("register.html", max_len=MAX_USERNAME_LENGTH)

if __name__ == '__main__':
    app.secret_key = SECRET_KEY
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.jinja_env.filters['datetimeformat'] = format_datetime
    app.jinja_env.filters['datetimeelapsedformat'] = format_elapsed_datetime
    app.run(debug=True)
    
