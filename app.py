import base64
import os
import hashlib
import requests
import stripe
from dotenv import load_dotenv

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename

load_dotenv()

# App Init
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SECURITY_PASSWORD_SALT'] = os.getenv("SECURITY_PASSWORD_SALT")
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
app.config['ALLOWED_EXTENSIONS'] = os.getenv('ALLOWED_EXTENSIONS')
app.config['SERVER_NAME'] = os.getenv('SEVER_NAME')
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
app.config['STRIPE_SECRET_KEY'] = os.getenv('STRIPE_SECRET_KEY')
app.config['STRIPE_PUBLISHABLE_KEY'] = os.getenv('STRIPE_PUBLISHABLE_KEY')
app.config['MAILGUN_API_KEY'] = os.getenv('MAILGUN_API_KEY')



stripe.api_key = app.config['STRIPE_SECRET_KEY']

mail = Mail(app)

def send_confirmation_email(email, subject, message):
    api_key = app.config['MAILGUN_API_KEY']
    domain = "sandboxfe7ca831d8a24a83bd09ff8f395b377c.mailgun.org"
    sender_email = f"Excited User <mailgun@{domain}>"

    response = requests.post(
        f"https://api.mailgun.net/v3/{domain}/messages",
        auth=("api", api_key),
        data={
            "from": sender_email,
            "to": [email],
            "subject": subject,
            "text": message,
            "html": f"<html><body><p>{message}</p></body></html>"
        }
    )

    if response.status_code != 200:
        raise Exception(f"Failed to send email: {response.json()}")
    return response

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Function to check allowed extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_snippet_link(snippet_id):
    # Encode the ID as a base64 URL-safe string
    token = base64.urlsafe_b64encode(str(snippet_id).encode('utf-8')).decode('utf-8')
    # Return the full URL by prepending the domain
    return f"https://vexara.pythonanywhere.com/view_snippet/{token}"

def send_notification(user, message):
    notification = Notification(user_id=user.id, message=message)
    db.session.add(notification)
    db.session.commit()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(120), default='default.jpg')  # Add default image
    bio = db.Column(db.String(500), default='')  # Bio field
    snippets = db.relationship('Snippet', back_populates='user')
    followers = db.relationship('Follow', back_populates='followed_user', foreign_keys='Follow.followed_user_id')
    following = db.relationship('Follow', back_populates='follower_user', foreign_keys='Follow.follower_user_id')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    likes = db.relationship('Like', backref='liked_by_user', lazy='dynamic')  # Changed 'user' to 'liked_by_user'
    saves = db.relationship('Save', backref='saved_by_user', lazy='dynamic')  # Changed 'user' to 'saved_by_user'

    credits = db.Column(db.Integer, default=0)  # Field to store credits
    is_diamond_member = db.Column(db.Boolean, default=False)  # Diamond membership flag

    def get_id(self):
        return str(self.id)

    # Method to check if user can post a snippet
    def can_post_snippet(self):
        return self.is_diamond_member or self.credits > 0

    @staticmethod
    def generate_token(email):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

    @staticmethod
    def confirm_token(token, expiration=3600):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
            return email
        except Exception:
            return False


class Snippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(60), nullable=False)
    content = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(60), nullable=False)
    tags = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='snippets')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    like_count = db.Column(db.Integer, default=0)
    save_count = db.Column(db.Integer, default=0)

    # Likes and Saves relationships
    liked_by = db.relationship('Like', back_populates='snippet')
    saved_by = db.relationship('Save', back_populates='snippet')


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    snippet_id = db.Column(db.Integer, db.ForeignKey('snippet.id'), nullable=False)
    user = db.relationship('User', back_populates='likes', foreign_keys=[user_id])  # 'likes' relationship
    snippet = db.relationship('Snippet', back_populates='liked_by')


class Save(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    snippet_id = db.Column(db.Integer, db.ForeignKey('snippet.id'), nullable=False)
    user = db.relationship('User', back_populates='saves', foreign_keys=[user_id])  # 'saves' relationship
    snippet = db.relationship('Snippet', back_populates='saved_by')


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    follower_user = db.relationship('User', back_populates='following', foreign_keys=[follower_user_id])
    followed_user = db.relationship('User', back_populates='followers', foreign_keys=[followed_user_id])


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def __repr__(self):
        return f"<Notification {self.message}>"


app.jinja_env.globals['generate_snippet_link'] = generate_snippet_link


# Routes
@app.route("/")
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        if username and email and password:
            new_user = User(username=username, email=email, hashed_password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            # Generate email confirmation token
            token = new_user.generate_token(new_user.email)  # Pass only email here

            # Send confirmation email
            confirm_url = url_for('confirm_email', token=token, _external=True)
            subject = "Please confirm your email"
            body = f"Click the following link to confirm your email: {confirm_url}"

            send_confirmation_email(email, subject, body)

            flash('A confirmation email has been sent to your email address.', 'info')
            return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    email = User.confirm_token(token)
    if email is False:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()  # Fetch user from DB by email
    if user is None:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    user.is_active = True  # Activate user
    db.session.commit()
    flash('Your account has been confirmed!', 'success')
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.hashed_password, password):
            if user.is_active:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Please confirm your email before logging in.', 'warning')
                return redirect(url_for('login'))
        flash('Login failed. Please check your email or password.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    snippets = Snippet.query.filter_by(user_id=current_user.id).all()

    # Get follower and following counts for the current user
    followers_count = len(current_user.followers)
    following_count = len(current_user.following)

    # Get unread notifications
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()

    if request.method == "POST":
        title = request.form['title']
        content = request.form['content']
        language = request.form['language']
        tags = request.form['tags']

        new_snippet = Snippet(title=title, content=content, language=language, tags=tags, user_id=current_user.id)
        db.session.add(new_snippet)
        db.session.commit()

        return redirect(url_for('dashboard'))  # Redirect to refresh the page after adding

    return render_template('dashboard.html', snippets=snippets, followers_count=followers_count,
                           following_count=following_count, notifications=notifications)




@app.route('/create_snippet', methods=['POST', 'GET'])
@login_required
def create_snippet():
    if not current_user.can_post_snippet():
        flash('You need credits to post a snippet. Purchase credits or subscribe as a Diamond Member.', 'danger')
        return redirect(url_for('purchase_credits'))  # Redirect to purchase page if no credits

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        language = request.form['language']
        tags = request.form['tags']

        new_snippet = Snippet(
            title=title,
            content=content,
            language=language,
            tags=tags,
            user_id=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.session.add(new_snippet)

        # Deduct credits if not a diamond member
        if not current_user.is_diamond_member:
            current_user.credits -= 1

        db.session.commit()
        flash('Snippet created successfully!', 'success')
        return redirect(url_for('dashboard'))  # Redirect to dashboard after snippet is created

    return render_template('create_snippet.html')


@app.route('/update_snippet/<int:id>', methods=['GET', 'POST'])
def update_snippet(id):
    snippet = Snippet.query.get(id)
    if request.method == 'POST':
        snippet.title = request.form['title']
        snippet.content = request.form['content']
        snippet.language = request.form['language']
        snippet.tags = request.form['tags']

        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('update_snippet.html', snippet=snippet)


@app.route('/delete_snippet/<int:id>', methods=['POST'])
def delete_snippet(id):
    snippet = Snippet.query.get(id)
    db.session.delete(snippet)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/home', methods=['GET', 'POST'])
def home():
    unclean_snippets = Snippet.query.all()

    snippets = []

    for snippet in unclean_snippets:
        snippet.content = snippet.content.strip()
        db.session.commit()
        snippets.append(snippet)

    user_likes = {snippet.id: Like.query.filter_by(user_id=current_user.id, snippet_id=snippet.id).first() for snippet in snippets}
    user_saves = {snippet.id: Save.query.filter_by(user_id=current_user.id, snippet_id=snippet.id).first() for snippet in snippets}

    return render_template('home.html', snippets=snippets, user_likes=user_likes, user_saves=user_saves)


@app.route('/like_snippet/<int:id>', methods=['POST'])
@login_required
def like_snippet(id):
    snippet = Snippet.query.get_or_404(id)
    existing_like = Like.query.filter_by(user_id=current_user.id, snippet_id=snippet.id).first()

    if existing_like:
        # Unlike the snippet
        db.session.delete(existing_like)
        snippet.like_count -= 1
    else:
        # Like the snippet
        like = Like(user_id=current_user.id, snippet_id=snippet.id)
        db.session.add(like)
        snippet.like_count += 1

        # Add a notification for the snippet author
        if current_user.id != snippet.user_id:
            notification_message = f"{current_user.username} liked your snippet '{snippet.title}'"
            notification = Notification(user_id=snippet.user_id, message=notification_message)
            db.session.add(notification)

    db.session.commit()
    return redirect(url_for('home'))



@app.route('/save_snippet/<int:id>', methods=['POST'])
@login_required
def save_snippet(id):
    snippet = Snippet.query.get_or_404(id)
    existing_save = Save.query.filter_by(user_id=current_user.id, snippet_id=snippet.id).first()
    if existing_save:
        # Unsave the snippet
        db.session.delete(existing_save)
        snippet.save_count -= 1
    else:
        # Save the snippet
        save = Save(user_id=current_user.id, snippet_id=snippet.id)
        db.session.add(save)
        snippet.save_count += 1
        notification_message = f'{current_user.username} Saved your Snippet: {snippet.title}'
        send_notification(snippet.user, notification_message)

    db.session.commit()
    return redirect(url_for('home'))  # Or redirect to snippet detail page


@app.route('/follow_user/<int:id>', methods=['POST'])
@login_required
def follow_user(id):
    user_to_follow = User.query.get_or_404(id)
    if not Follow.query.filter_by(follower_user_id=current_user.id, followed_user_id=user_to_follow.id).first():
        follow = Follow(follower_user_id=current_user.id, followed_user_id=user_to_follow.id)
        db.session.add(follow)
        db.session.commit()
        notification_message = f"{current_user.username} Started Following You!"
        send_notification(user_to_follow, notification_message)
    return redirect(url_for('view_profile', id=user_to_follow.id))

@app.route('/liked_snippets')
@login_required
def liked_snippets():
    liked_snippets = Snippet.query.join(Like).filter(Like.user_id == current_user.id).all()
    return render_template('liked_snippets.html', snippets=liked_snippets)

@app.route('/saved_snippets')
@login_required
def saved_snippets():
    saved_snippets = Snippet.query.join(Save).filter(Save.user_id == current_user.id).all()
    return render_template('saved_snippets.html', snippets=saved_snippets)

@app.route('/user_profile/<int:id>')
@login_required
def view_profile(id):
    user = User.query.get_or_404(id)
    snippets = Snippet.query.filter_by(user_id=user.id).all()

    # Get follower and following counts for the user
    followers_count = len(user.followers)
    following_count = len(user.following)

    return render_template('user_profile.html',
                           user=user,
                           snippets=snippets,
                           followers_count=followers_count,
                           following_count=following_count)



@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        # Handle bio update
        bio = request.form.get('bio')
        current_user.bio = bio

        # Handle profile image update
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)

                upload_folder = os.path.join(app.config['UPLOAD_FOLDER'])

                # Check if the directory exists, if not, create it
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)

                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.profile_image = filename

        # Commit changes to the database
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('update_profile.html')


@app.route('/follow/<int:id>', methods=['POST'])
@login_required
def follow(id):
    target_user = User.query.get_or_404(id)

    # Check if the user is already following the target user
    existing_follow = Follow.query.filter_by(follower_user_id=current_user.id, followed_user_id=target_user.id).first()

    if existing_follow:
        # If already following, unfollow by deleting the follow relationship
        db.session.delete(existing_follow)
        action = 'unfollow'
    else:
        # If not following, follow by adding the follow relationship
        new_follow = Follow(follower_user_id=current_user.id, followed_user_id=target_user.id)
        db.session.add(new_follow)
        action = 'follow'
        notification_message = f"{current_user.username} Started Following You!"
        send_notification(target_user, notification_message)

    db.session.commit()

    # Get updated follower and following counts
    followers_count = len(target_user.followers)
    following_count = len(target_user.following)

    # Return a JSON response with the updated data
    return jsonify({
        'action': action,
        'followers_count': followers_count,
        'following_count': following_count
    })

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/share_snippet/<int:id>')
def share_snippet(id):
    snippet = Snippet.query.get_or_404(id)
    # Generate the sharable link
    sharable_link = generate_snippet_link(snippet.id)
    return render_template('share_snippet.html', snippet=snippet, sharable_link=sharable_link)

@app.route('/view_snippet/<string:token>')
def view_snippet(token):
    try:
        # Decode the base64 URL-safe token back into the snippet ID
        snippet_id = int(base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8'))
        snippet = Snippet.query.get_or_404(snippet_id)
        return render_template('view_snippet.html', snippet=snippet)
    except Exception as e:
        # Handle invalid or malformed tokens
        print(f"Error: {e}")  # For debugging purposes
        return "Invalid snippet link", 400

@app.route('/mark_as_read/<int:id>')
@login_required
def mark_as_read(id):
    notification = Notification.query.get(id)
    notification.is_read = True
    db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()

    return redirect(url_for('dashboard'))


# Route for purchasing credits
@app.route('/purchase_credits', methods=['GET', 'POST'])
@login_required
def purchase_credits():
    if request.method == 'POST':
        credits_to_purchase = int(request.form['credits'])  # The number of credits to purchase

        # Create a Stripe Checkout session for the credit purchase
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'usd',  # You can change this to your desired currency
                        'product_data': {
                            'name': f'{credits_to_purchase} Credits',
                        },
                        'unit_amount': credits_to_purchase * 100,  # Amount in cents
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('payment_cancel', _external=True),
        )

        # Redirect to Stripe Checkout page
        return redirect(checkout_session.url)

    return render_template('purchase_credits.html')

# Route for subscribing to diamond membership
@app.route('/subscribe_diamond', methods=['GET', 'POST'])
@login_required
def subscribe_diamond():
    if request.method == 'POST':
        # Create a Stripe Checkout session for the Diamond Membership
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'usd',  # You can change this to your desired currency
                        'product_data': {
                            'name': 'Diamond Membership',
                        },
                        'unit_amount': 5000,  # Amount in cents (e.g., $50.00)
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=url_for('diamond_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('payment_cancel', _external=True),
        )

        # Redirect to Stripe Checkout page
        return redirect(checkout_session.url)

    return render_template('subscribe_diamond.html')

@app.route('/diamond_success')
def diamond_success():
    session_id = request.args.get('session_id')

    # Retrieve the session to verify the payment
    session = stripe.checkout.Session.retrieve(session_id)

    if session.payment_status == 'paid':
        # Grant the user Diamond membership
        current_user.is_diamond_member = True
        current_user.credits = float('inf')  # Or set a large number of credits
        db.session.commit()
        flash('You have successfully subscribed to Diamond Membership!', 'success')

    return redirect(url_for('dashboard'))


@app.route('/payment_success')
def payment_success():
    session_id = request.args.get('session_id')

    # Retrieve the session to verify the payment
    session = stripe.checkout.Session.retrieve(session_id)

    if session.payment_status == 'paid':
        credits = int(session.amount_total) / 100  # Convert cents to dollars
        current_user.credits += credits  # Update user credits
        db.session.commit()
        flash(f'You have successfully purchased {credits} credits.', 'success')

    return redirect(url_for('dashboard'))

@app.route('/payment_cancel')
def payment_cancel():
    flash('Payment was canceled. Please try again.', 'danger')
    return redirect(url_for('dashboard'))



@app.route('/update_profile_image', methods=['POST'])
@login_required
def update_profile_image():
    if 'profile_image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['profile_image']

    # Check if file is selected
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the file is allowed
    if file and allowed_file(file.filename):
        # Secure the filename to prevent directory traversal attacks
        filename = secure_filename(file.filename)

        # Create the path where the file will be stored
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Save the file to the specified directory
        file.save(filepath)

        # Update the user's profile image in the database
        current_user.profile_image = filename
        db.session.commit()

        flash('Profile image updated successfully!', 'success')
        send_notification(current_user, "Profile Picture Has been Updated!")
        return redirect(url_for('dashboard'))

    else:
        flash('Allowed file types are png, jpg, jpeg, gif', 'danger')
        return redirect(url_for('dashboard'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
