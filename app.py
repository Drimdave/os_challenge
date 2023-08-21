from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Flask configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///os_challenge.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['SECRET_KEY'] = 'a_random_string'

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), default='user')

class RecordedRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payload = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Custom decorator for role-based access
def role_required(role):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()
            if user and user.role == role:
                return fn(*args, **kwargs)
            else:
                return jsonify({"message": "Access forbidden: role required"}), 403
        return wrapper
    return decorator

@app.route('/')
def index():
    return jsonify({
        "message": "Welcome to the OS Challenge API!",
        "endpoints": {
            "/record": "POST: Record a JSON payload",
            "/requests": "GET: Retrieve all recorded requests",
            "/register": "POST: Register a new user",
            "/login": "POST: Login and retrieve a token"
        }
    })

@app.route('/record', methods=['POST'])
def record_request():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No JSON payload received"}), 400
    recorded_request = RecordedRequest(payload=str(data))
    db.session.add(recorded_request)
    db.session.commit()
    return jsonify({"message": "Request recorded successfully"}), 201

@app.route('/requests', methods=['GET'])
def get_requests():
    all_requests = RecordedRequest.query.all()
    return jsonify([{"id": req.id, "payload": req.payload, "timestamp": req.timestamp} for req in all_requests])

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify({"message": "Both username and password are required."}), 400
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"message": "Username already exists."}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully."}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return jsonify({"message": "Both username and password are required."}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password."}), 401

    # Create the access token
    access_token = create_access_token(identity=user.username)

    # You can store the token in session for later use
    session['access_token'] = access_token

    # Redirect to the dashboard
    return redirect(url_for('dashboard'))

@app.route('/admin-endpoint', methods=['GET'])
@role_required('admin')
def admin_endpoint():
    return jsonify(message="Welcome, admin!")

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/request-reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            session['reset_token'] = 'mock_token'
            return redirect(url_for('reset_password'))
        else:
            return "User not found", 404
    return render_template('request_reset.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_token' not in session:
        return "Invalid reset link", 403
    if request.method == 'POST':
        new_password = request.form.get('password')
        # Here, you'd normally validate the token from the email link.
        # We'll just check our mock token.
        if session['reset_token'] == 'mock_token':
            # In a real-world scenario, you'd identify the user either through the token or additional user input.
            # Here, for simplicity, we're just going to reset the password for a hardcoded user.
            user = User.query.first()
            if user:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                session.pop('reset_token', None)  # Clear the token
                return redirect(url_for('login'))
            else:
                return "User not found", 404
        else:
            return "Invalid reset token", 403
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
