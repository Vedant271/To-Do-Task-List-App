# Import necessary modules and libraries
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import re

# Initialize the Flask app
app = Flask(__name__)

# Set a secret key for session management
app.secret_key = 'secretkey'

# MongoDB connection
client = MongoClient("mongodb://127.0.0.1:27017/")

# Create a database instance
db = client["usersTasks"]

# Create collections within MongoDB "usersTasks" database
users_collection = db["users"]
tasks_collection = db["tasks"]

# Define a route for the home page
@app.route('/')
def home():
    return render_template('home.html')

# Define a route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get user input from the registration form
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # User input validations
        # Checks if input is empty
        if not username:
            flash('Username is required', 'danger')
        # Checks if input contains only alphabetical characters
        elif not re.search(r'[a-zA-Z]', username):
            flash('Username must contain at least one letter', 'danger')
        # Checks if username already exists database or not
        elif users_collection.find_one({"username": username}):
            flash('Username already exists', 'danger')
        # Checks if input password is atleast 6 digit long
        elif len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
        # Checks if both 'Password' and 'Confirm Password' input matches
        elif password != confirm_password:
            flash('Passwords do not match','danger')
        else:
            # Hash the password before saving it in the database
            hashed_password = generate_password_hash(password, method='sha256')
            users_collection.insert_one({"username": username, "password": hashed_password})
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# Define a route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get user input from the login form
        username = request.form['username']
        password = request.form['password']

        # Find the user in the database
        user = users_collection.find_one({"username": username})

        # Check if the user exists and the password is correct
        if user and check_password_hash(user["password"], password):
            # Create a session to track the user's login status
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful', 'success')
            return redirect(url_for('tasks'))
        else:
            flash('Login failed. Check your credentials', 'danger')
    return render_template('login.html')

# Define a route for user logout
@app.route('/logout')
def logout():
    # Clear the user's session data to log them out
    session.clear()
    return redirect(url_for('home'))

# Define a route to render tasks page containing components like search tasks, form to add task, tasks list and logout button
@app.route('/tasks')
def tasks():
    # Find the user based on their session username
    user = users_collection.find_one({'username': session['username']})
    if user:
        user_id = user['_id']
        # Find tasks associated with the user
        tasks = tasks_collection.find({'user_id': user_id})
        return render_template('tasks.html', user=user, tasks=tasks)

# Define a route to add a new task
@app.route('/add', methods=['POST'])
def add_task():
    user = users_collection.find_one({'username': session['username']})
    if user:
        # Get the task name from the form
        task_name = request.form.get('task')
        user_id = user['_id']
        # Insert the new task into the database
        tasks_collection.insert_one({'task_name': task_name, 'user_id': user_id})
        return redirect(url_for('tasks'))

# Define a route for searching user tasks
@app.route('/search', methods=['GET'])
def search():
    user = users_collection.find_one({'username': session['username']})
    if user:
        user_id = user['_id']
        # Get the search query
        query = request.args.get('query', '')
        # Use a regular expression to search for tasks containing the query (case-insensitive)
        tasks = tasks_collection.find({'user_id': user_id, 'task_name': {'$regex': query, '$options': 'i'}})
        return render_template('tasks.html', user=user, tasks=tasks)

# Define a route to update a task
@app.route('/update/<string:task_id>', methods=['GET', 'POST'])
def update_task(task_id):
    task = tasks_collection.find_one({'_id': ObjectId(task_id)})
    if request.method == 'POST':
        # Get the new task name from the form
        new_task_name = request.form.get('new_task_name')
        # Update the task with the new name
        tasks_collection.update_one({'_id': ObjectId(task_id)}, {'$set': {'task_name': new_task_name}})
        return redirect(url_for('tasks'))
    return render_template('update.html', task=task)

# Define a route to delete a task
@app.route('/delete/<string:task_id>')
def delete_task(task_id):
    # Delete the task based on its unique ObjectId
    tasks_collection.delete_one({'_id': ObjectId(task_id)})
    return redirect(url_for('tasks'))

# Custom error handlers for different HTTP error codes, like
# For error code 400
@app.errorhandler(400)
def internal_server_error(e):
    return render_template('400.html'), 400

# For error code 404
@app.errorhandler(404)
def internal_server_error(e):
    return render_template('404.html'), 404

# For error code 500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# Running Flask application
if __name__ == '__main__':
    app.run(debug=True)