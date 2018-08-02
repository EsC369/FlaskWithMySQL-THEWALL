import re
import hashlib
from flask import Flask, render_template, redirect, request, flash, session

from mysqlconnection import MySQLConnector

app = Flask(__name__)

mysql = MySQLConnector(app, 'thewall')
app.secret_key = 'lkjasasdasdas52345'

#This is the login page which uses the /login route
@app.route('/')
def index():
    return render_template('login.html')
@app.route('/login')
def reg():
    return render_template('login.html')

#This is the login route which processes the login
@app.route('/login', methods=['GET', 'POST'])
def login():
    #get the user data from the db based on the email address the user typed
    query = "SELECT * from users where email = :email LIMIT 1"
    data = {
        'email': request.form['email']
    }
    get_user = mysql.query_db(query, data)
    #Check the user info and password
    if get_user:
        session['userid'] = get_user[0]['id']
        session['user_first_name'] = get_user[0]['first_name']
        hashed_password = get_user[0]['password']
        pw_hash = hashlib.sha224(request.form['password']).hexdigest()
        if hashed_password == pw_hash:
            session['logged_in'] = True
            flash("You successfully logged in!")
            return redirect('/thewall')
        else:
            session['logged_in'] = False
            flash("Login failed! Try again, or register.")
            return redirect('/')
    else:
        flash("Your username (email) was not found, please try again or register")
        return redirect('/')

#This is the home page logout button, where the user will logout.
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    flash("You have been logged out... ")
    return redirect('/')

#This is the register page, where the user will register for an account.
@app.route('/newUser', methods=['POST'])
def register():
    error = 0
    if request.method == 'POST':
        #check first name (2 chars, submitted, and letters only)
        first_name = request.form['first_name']
        if not first_name:
            error += 1
            flash("You myst supply a First Name")
        elif not first_name.isalpha():
            error += 1
            flash("First Name must contain letters only.")
        elif len(first_name) < 3:
            error += 1
            flash("First Name must contain more than 2 characters.")
        #check last name (2 chars, submitted, and letters only)
        last_name = request.form['last_name']
        if not last_name:
            error += 1
            flash("You must supply a Last Name")
        elif not last_name.isalpha():
            error += 1
            flash("Last Name must contain letters only.")
        elif len(last_name) < 3:
            error += 1
            flash("Last Name must contain more than 2 characters.")
        #check email
        email = request.form['email']
        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            error += 1
            flash("Invalid Email Address detected.")
        #check password and confirm password
        user_password = request.form['user_password']
        confirm_password = request.form['confirm_password']
        if not user_password:
            error += 1
            flash("You must supply a password.")
        elif not confirm_password:
            error += 1
            flash("You must supply a confirm password")
        if user_password != confirm_password:
            error += 1
            flash("Passwords do not match.")
        elif len(user_password) < 8:
            error += 1
            flash("Password must be at least 8 characters long.")
        #prior to the insert, cache and return any errors.
        if error > 0:
            return redirect('/login')
        else:
            pw_hash = hashlib.sha224(user_password).hexdigest()
            query = "INSERT INTO users (first_name, last_name, email, password, created_at, \
                                        updated_at) values (:first_name, :last_name, :email, \
                                        :password, now(), now())"
            data = {
                'first_name': first_name, 'last_name': last_name, \
                'email': email, 'password': pw_hash}
            mysql.query_db(query, data)
            session['logged_in'] = True
            return redirect('/thewall')
    else:
        if request.method == 'GET':
        #exit on fail to main login page with flash error
            return render_template('login.html')

#This is the home page, after login with welcome message for the user that they are logged in
# @app.route('/thewall')
# def thewall():
#     #check for session
#     if not session['logged_in']:
#         flash("Your are not logged in, please login or register.")
#         return redirect('/')
#     else:
#         return render_template('thewall.html')

# THE WALL
@app.route('/thewall')
def thewall():
    print(session)  
    if 'user' in session:
        query = "SELECT first_name, last_name, message_text, DATE_FORMAT(messages.created_at, '%M %D %Y %H:%i') AS created_at, messages.id, user_id FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
        message_list = mysql.query_db(query)
        print(message_list)
        query = "SELECT first_name, last_name, comment_text, DATE_FORMAT(comments.created_at, '%M %D %Y %H:%i') AS created_at, message_id FROM comments JOIN users ON comments.user_id = users.id ORDER BY comments.created_at"
        comment_list = mysql.query_db(query)
        print (comment_list)
        return render_template('/thewall.html', message_list = message_list, comment_list = comment_list) 
    else:
        flash("You are not logged in")
        return redirect('/')

@app.route('/thewall/message', methods=['POST'])
def add_message():
    message_text = request.form['message']
    query = "INSERT INTO messages (message_text, created_at, updated_at, user_id) VALUES (:message_text, Now(), Now(), :user_id)"
    data = {
        'message_text': message_text,
        'user_id': session['user']['id']
    }
    mysql.query_db(query, data)
    return redirect('/thewall')

@app.route('/thewall/comment/<message_id>', methods=['POST'])
def add_comment(message_id):
    query = "INSERT INTO comments (comment_text, created_at, updated_at, user_id, message_id) VALUES (:comment_text, Now(), Now(), :user_id, :message_id)"
    data = {
        'comment_text': request.form['comment'],
        'user_id': session['user']['id'],
        'message_id': message_id
    }
    mysql.query_db(query, data)
    return redirect('/thewall')

@app.route('/thewall/message/delete/<id>')
def delete_comment(id):
    del_comments_query = "DELETE FROM comments WHERE message_id = :id"
    data = {
        'id': id
    }
    mysql.query_db(del_comments_query, data)
    del_message_query = "DELETE FROM messages WHERE id = :id"
    mysql.query_db(del_message_query, data)
    return redirect('/thewall')
        
app.run(debug=True)