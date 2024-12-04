from flask import Flask, request, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from cv_jsoner import extract_structured_content, run_model
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import requests
import base64
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from flask import jsonify
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound, Forbidden
import logging
from enum import Enum
from sqlalchemy import Enum as SQLAlchemyEnum
from paddle_billing import Client, Environment, Options
from paddle_billing.Resources.Subscriptions import Operations as SubscriptionOperations
from paddle_billing.Resources.Transactions import Operations as TransactionOperations
from paddle_billing.Entities.Subscriptions import SubscriptionEffectiveFrom
from paddle_billing.Entities.Transactions import TransactionCreateItem
from paddle_billing.Resources.Prices import Operations as PriceOperations
import secrets
from sqlalchemy import and_
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(filename='/var/log/cvify_app.log', level=logging.DEBUG)

static_folder = 'static'

app = Flask(__name__, static_url_path='', static_folder=static_folder)
CORS(app, supports_credentials=True, origins=['chrome-extension://*'])

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cv_generator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Add these configurations
app.config['PIC_FOLDER'] = 'profile_pictures'
app.config['PIC_UPLOAD_FOLDER'] = os.path.join(static_folder, app.config['PIC_FOLDER'])
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.config['PADDLE_PRODUCTS'] = {
    'pro_01jawqkzvyk39n2nrprmpdja7c': {
        'name': 'extractions',
        'prices': {
            'pri_01jawqp5xhcj4akwwx1fv90khn': 10,
            'pri_01jawqqq7y1jerrth6m03td1zj': 50
        }
    },
    'pro_01jaqparwy6wqpb0qd5gtcbvkp': {
        'name': 'subscription',
        'prices': {
            'pri_01jaqpemr2mj9w091g0698fz2g': 1,
            'pri_01jawqy5jz6t5yd9vv99fgny8j': 12
        }
    }
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def download_and_save_image(image_url, update_filename=None):
    if not image_url:
        return None
    
    if update_filename:
        filename = update_filename
    elif image_url.startswith('data:'):
        filename = "profile_picture.png"
    else:
        filename = secure_filename(os.path.basename(urlparse(image_url).path))
    
    # Create the directory if it doesn't exist
    os.makedirs(app.config['PIC_UPLOAD_FOLDER'], exist_ok=True)
    
    store_filepath = os.path.join(app.config['PIC_UPLOAD_FOLDER'], filename)
    if update_filename is None:
        # Check for existing files and increment counter until we find an unused filename
        counter = 0
        base_name, extension = os.path.splitext(filename)
        while os.path.exists(store_filepath):
            counter += 1
            filename = f"{base_name}{counter}{extension}"
            store_filepath = os.path.join(app.config['PIC_UPLOAD_FOLDER'], filename)
    download_filepath = os.path.join(app.config['PIC_FOLDER'], filename)
    
    if image_url.startswith('data:'):
        with open(store_filepath, 'wb') as f:
            f.write(base64.b64decode(image_url.split(",")[1]))
    else:
        if not allowed_file(filename):
            return None
        response = requests.get(image_url)
        if response.status_code != 200:
            return None
        
        with open(store_filepath, 'wb') as f:
            f.write(response.content)
    
    return download_filepath

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define models
class UserTier(Enum):
    FREE = 'free'
    PREMIUM = 'premium'
    DEV = 'dev'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    tier = db.Column(SQLAlchemyEnum(UserTier), default=UserTier.FREE, nullable=False)
    extractions_left = db.Column(db.Integer, default=10, nullable=False)
    paid_extractions_left = db.Column(db.Integer, default=0, nullable=False)
    subscription_id = db.Column(db.String(255), nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    subscription_next_billing = db.Column(db.DateTime, nullable=True)
    next_reset_date = db.Column(db.DateTime, nullable=False,)
    cvs = db.relationship('CV', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def reset_extractions(self):
        self.next_reset_date = datetime.utcnow() + timedelta(days=30)
        self.extractions_left = 100 if self.tier == UserTier.PREMIUM else 10

    def deduct_extraction(self):
        if self.extractions_left > 0:
            self.extractions_left -= 1
        elif self.paid_extractions_left > 0:
            self.paid_extractions_left -= 1
        else:
            raise BadRequest('No extractions left')
        if self.is_dev and self.extractions_left == 0:
            self.extractions_left = 10000

    @property
    def total_extractions(self):
        return self.extractions_left + self.paid_extractions_left
    
    @property
    def can_extract(self):
        return self.total_extractions > 0

    @property
    def is_premium(self):
        return self.tier == UserTier.PREMIUM
    
    @property
    def is_dev(self):
        return self.tier == UserTier.DEV

    def upgrade_to_premium(self, subscription_id, months=1, ends_at=None):
        if self.is_dev:
            return
        self.subscription_id = subscription_id
        if ends_at:
            ends_at = datetime.fromisoformat(ends_at.replace('Z', '+00:00'))
            self.subscription_end = ends_at
            self.subscription_next_billing = ends_at
        else:
            try:
                paddle_subscription = paddle.subscriptions.get(subscription_id)
                self.subscription_end = paddle_subscription.current_billing_period.ends_at
                self.subscription_next_billing = paddle_subscription.next_billed_at
            except:
                if self.subscription_id:
                    self.subscription_end += timedelta(days=30 * months)
                else:
                    self.subscription_end = datetime.utcnow() + timedelta(days=2)
        self.tier = UserTier.PREMIUM
        self.reset_extractions()

    def downgrade_to_free(self):
        if self.is_dev:
            return
        self.tier = UserTier.FREE
        self.subscription_id = None
        self.subscription_end = None
        self.subscription_next_billing = None
        self.reset_extractions()
    
    def upgrade_to_dev(self):
        self.tier = UserTier.DEV
        self.extractions_left = 10000

class CV(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    source_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    name = db.Column(db.String(200), nullable=True)

class Token(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.String(255), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    paddle_customer_id = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

paddle = Client(os.getenv('PADDLE_API_KEY'), options=Options(environment=Environment.SANDBOX))

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user:
        return jsonify({'message': 'User already exists'}), 400
    new_user = User(email=data['email'])
    new_user.set_password(data['password'])
    new_user.next_reset_date = datetime.utcnow() + timedelta(days=30)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    logging.debug(f"Login attempt for user: {data.get('email')}")
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        session['user_id'] = user.id
        logging.debug(f"User {user.id} logged in successfully")
        return jsonify({'message': 'Logged in successfully'}), 200
    logging.debug("Login failed")
    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/process', methods=['POST'])
def process_html():
    if 'user_id' not in session:
        raise Unauthorized('You must be logged in to process HTML')
    
    user = User.query.get(session['user_id'])
    if not user.can_extract:
        raise BadRequest('No extractions left')

    html = request.json['html']
    source_url = request.json.get('source_url')

    structured_content = extract_structured_content(html, False)
    cv_data = run_model(structured_content)

    if 'profile_picture' in cv_data:
        local_image_path = download_and_save_image(cv_data['profile_picture'])
        if local_image_path:
            cv_data['profile_picture'] = local_image_path

    name = f"{cv_data.get('name', 'Unnamed')} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    new_cv = CV(user=user, data=cv_data, source_url=source_url, name=name)
    
    try:
        db.session.add(new_cv)
        user.deduct_extraction()
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        if local_image_path:
            os.remove(local_image_path)
        app.logger.error(f"Database error in process_html: {str(e)}")

    return jsonify(cv_data)

@app.route('/user_cvs', methods=['GET'])
def get_user_cvs():
    if 'user_id' not in session:
        logging.debug("User not in session")
        return jsonify({'message': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    cvs = [{'id': cv.id, 'name': cv.name, 'created_at': cv.created_at.isoformat()} for cv in user.cvs]
    return jsonify(cvs)

@app.route('/cv/<int:cv_id>', methods=['GET'])
def get_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    
    cv = CV.query.get_or_404(cv_id)
    if cv.user_id != session['user_id']:
        return jsonify({'message': 'Unauthorized'}), 401
    
    return jsonify(cv.data)

@app.route('/cv/<int:cv_id>', methods=['DELETE'])
def delete_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    
    cv = CV.query.get_or_404(cv_id)
    if cv.user_id != session['user_id']:
        return jsonify({'message': 'Unauthorized'}), 401
    
    db.session.delete(cv)
    db.session.commit()

    if cv.data.get('profile_picture'):
        os.remove(os.path.join(app.config['PIC_UPLOAD_FOLDER'], os.path.basename(cv.data['profile_picture'])))
    
    return jsonify({'message': 'CV deleted successfully'}), 200

@app.route('/create_cv', methods=['POST'])
def create_cv():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    cv_data = request.json
    
    # Generate a name for the new CV
    cv_name = f"New CV - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    
    new_cv = CV(user=user, data=cv_data, name=cv_name)
    db.session.add(new_cv)
    db.session.commit()
    
    return jsonify({'message': 'CV created successfully', 'id': new_cv.id}), 201

@app.route('/cv/<int:cv_id>', methods=['PUT'])
def update_cv(cv_id):
    logging.debug(f"Starting update_cv for cv_id: {cv_id}")

    if 'user_id' not in session:
        logging.debug("User not in session, returning unauthorized")
        return jsonify({'message': 'Unauthorized'}), 401
    
    logging.debug(f"Looking up CV with id {cv_id}")
    cv = CV.query.get_or_404(cv_id)
    
    if cv.user_id != session['user_id']:
        logging.debug(f"CV user_id {cv.user_id} does not match session user_id {session['user_id']}")
        return jsonify({'message': 'Unauthorized'}), 401
    
    logging.debug("Getting CV data from request")
    cv_data = request.json

    if 'profile_picture' in cv_data and not cv_data['profile_picture'].startswith(app.config['PIC_FOLDER']):
        logging.debug("Processing new profile picture")
        old_filename = os.path.basename(cv.data['profile_picture']) if cv.data.get('profile_picture') else None
        local_image_path = download_and_save_image(cv_data['profile_picture'], old_filename)
        if local_image_path:
            logging.debug(f"Saved profile picture to {local_image_path}")
            cv_data['profile_picture'] = local_image_path
    
    try:
        logging.debug("Updating CV data and committing to database")
        cv.data = cv_data
        db.session.commit()
    except Exception as e:
        logging.error(f"Error updating CV: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while updating the CV'}), 500
    
    logging.debug("CV updated successfully")
    return jsonify({'message': 'CV updated successfully'}), 200

@app.route('/cv/<int:cv_id>/rename', methods=['POST'])
def rename_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        new_name = request.json.get('name')
        if not new_name or not isinstance(new_name, str):
            raise BadRequest('New name is required and must be a string')
        
        if len(new_name) > 200:  # Assuming max length of 200 characters
            raise BadRequest('New name is too long (max 200 characters)')
        
        cv = CV.query.get(cv_id)
        if not cv:
            raise NotFound('CV not found')
        
        if cv.user_id != session['user_id']:
            raise Unauthorized('You do not have permission to rename this CV')
        
        cv.name = new_name
        db.session.commit()
        
        return jsonify({'message': 'CV renamed successfully'}), 200
    
    except BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Unauthorized as e:
        return jsonify({'error': str(e)}), 401
    except NotFound as e:
        return jsonify({'error': str(e)}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error while renaming CV: {str(e)}")
        return jsonify({'error': 'An error occurred while renaming the CV'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error while renaming CV: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/cv/<int:cv_id>/duplicate', methods=['POST'])
def duplicate_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        original_cv = CV.query.get(cv_id)
        if not original_cv:
            raise NotFound('CV not found')
        
        if original_cv.user_id != session['user_id']:
            raise Unauthorized('You do not have permission to duplicate this CV')
        
        # Check if user has reached maximum allowed CVs (e.g., 10)
        user_cv_count = CV.query.filter_by(user_id=session['user_id']).count()
        if user_cv_count >= 10:
            raise BadRequest('You have reached the maximum number of allowed CVs')
        
        new_name = f"{original_cv.name} (Copy)"
        if len(new_name) > 200:
            new_name = new_name[:197] + "..."
        
        new_cv = CV(
            name=new_name,
            data=original_cv.data,
            user_id=session['user_id']
        )
        db.session.add(new_cv)
        db.session.commit()
        
        return jsonify({'message': 'CV duplicated successfully', 'id': new_cv.id}), 201
    
    except BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Unauthorized as e:
        return jsonify({'error': str(e)}), 401
    except NotFound as e:
        return jsonify({'error': str(e)}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error while duplicating CV: {str(e)}")
        return jsonify({'error': 'An error occurred while duplicating the CV'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error while duplicating CV: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/initiate_transaction', methods=['POST'])
def initiate_transaction():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = session['user_id']

    if user_id != data['userId']:
        return jsonify({'error': 'User ID mismatch'}), 401

    # Check if transaction already exists
    existing_transaction = Transaction.query.get(data['transactionId'])
    if existing_transaction:
        if existing_transaction.user_id != user_id:
            return jsonify({'error': 'Transaction exists but belongs to different user'}), 401
        return jsonify({'transactionId': existing_transaction.id}), 200

    # Create new transaction if it doesn't exist
    new_transaction = Transaction(
        id=data['transactionId'],
        user_id=user_id,
        paddle_customer_id=data['paddleCustomerId'],
        status='pending'
    )

    try:
        db.session.add(new_transaction)
        db.session.commit()
    except IntegrityError:
        # Handle race condition where transaction was created between check and insert
        db.session.rollback()
        existing_transaction = Transaction.query.get(data['transactionId'])
        if existing_transaction and existing_transaction.user_id != user_id:
            return jsonify({'error': 'Transaction exists but belongs to different user'}), 401
        return jsonify({'transactionId': existing_transaction.id}), 200

    return jsonify({'transactionId': new_transaction.id}), 200

@app.route('/confirm_transaction', methods=['POST'])
def confirm_transaction():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_id = session['user_id']

    try:
        # Use a database transaction to ensure atomicity
        with db.session.begin():
            transaction = Transaction.query.with_for_update().get(data['transactionId'])
            if not transaction:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if transaction.user_id != user_id:
                return jsonify({'error': 'User ID mismatch'}), 401
            
            if transaction.status == 'completed':
                return jsonify({'message': 'Transaction already completed'}), 200

            transaction.status = 'completed'
            update_user_benefits(user_id, data['transactionId'])

        return jsonify({'message': 'Transaction confirmed'}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Transaction could not be processed'}), 500

@app.route('/cancel_subscription', methods=['POST'])
def cancel_subscription():
    if 'user_id' not in session:
        raise Unauthorized('You must be logged in to cancel a subscription')

    user = User.query.get(session['user_id'])

    if not user:
        raise BadRequest('Invalid user')
    
    if user.is_dev:
        try:
            paddle.subscriptions.cancel(
                user.subscription_id,
                SubscriptionOperations.CancelSubscription(
                    SubscriptionEffectiveFrom("immediately")
                )
            )
            return jsonify({'message': 'Subscription cancelled successfully'}), 200
        except Exception as e:
            app.logger.error(f"Error cancelling subscription: {str(e)}")
            return jsonify({'error': 'Failed to cancel subscription'}), 500
    
    elif user.is_premium:
        try:
            paddle.subscriptions.cancel(
                user.subscription_id,
                SubscriptionOperations.CancelSubscription()
            )
            user.subscription_next_billing = None
            db.session.commit()
            return jsonify({'message': 'Subscription cancelled successfully'}), 200
        except Exception as e:
            app.logger.error(f"Error cancelling subscription: {str(e)}")
            return jsonify({'error': 'Failed to cancel subscription'}), 500
    else:
        return jsonify({'error': 'You are not a premium user'}), 403

@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        notification = request.json
        
        if notification['event_type'] == 'transaction.created':
            handle_transaction_created(notification['data'])
        elif notification['event_type'] == 'transaction.completed':
            handle_transaction_completed(notification['data'])
        elif notification['event_type'] == 'transaction.canceled':
            handle_transaction_canceled(notification['data'])
        elif notification['event_type'] == 'subscription.created':
            handle_subscription_created(notification['data'])
        elif notification['event_type'] in ['subscription.updated', 'subscription.activated']:
            handle_subscription_updated(notification['data'])
        elif notification['event_type'] in ['subscription.canceled', 'subscription.paused', 'subscription.past_due']:
            handle_subscription_canceled(notification['data'])
        
        return 'OK', 200
    except Exception as e:
        app.logger.error(f"Error processing webhook: {str(e)}")
        return 'Error', 400

def handle_subscription_created(data):
    try:
        user_id = data["custom_data"]["user_id"] if data["custom_data"].get("user_id") else Transaction.query.get(data['transaction_id']).user_id
    except:
        app.logger.error(f"handle_subscription_created: Error processing subscription: {data['id']}. User not found.")
        return
    user = User.query.get(user_id)
    if user:
        user.upgrade_to_premium(data['id'], ends_at=data['current_billing_period']['ends_at'])
        db.session.commit()
    else:
        app.logger.error(f"handle_subscription_created: User not found for ID: {user_id}")

def handle_subscription_updated(data):
    user = User.query.filter_by(subscription_id=data['id']).first()
    if user:
        user.subscription_end = datetime.fromisoformat(data['current_billing_period']['ends_at'].replace('Z', '+00:00'))
        user.subscription_next_billing = datetime.fromisoformat(data['next_billed_at'].replace('Z', '+00:00'))
        if not user.is_premium and user.subscription_end > datetime.utcnow():
            user.tier = UserTier.PREMIUM
        db.session.commit()
    else:
        app.logger.error(f"handle_subscription_updated: User not found for subscription: {data['id']}")

def handle_subscription_canceled(data):
    user = User.query.filter_by(subscription_id=data['id']).first()
    if user:
        user.downgrade_to_free()
        db.session.commit()
    else:
        app.logger.error(f"handle_subscription_canceled: User not found for subscription: {data['id']}")

def handle_transaction_created(data):
    try:
        user_id = data['custom_data']['user_id']
        user = User.query.get(user_id)
        if user is None:
            app.logger.error(f"User not found for ID: {user_id}")
            return
        
        transaction_id = data['id']
        transaction = Transaction.query.get(transaction_id)
        if transaction:
            return
                
        new_transaction = Transaction(
            id=transaction_id,
            user_id=user_id,
            paddle_customer_id=data['customer_id'],
            status='pending'
        )
        db.session.add(new_transaction)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"handle_transaction_created: Error processing transaction: {transaction_id}")

def handle_transaction_completed(data):
    try:
        transaction_id = data['id']
        # Use a database transaction to ensure atomicity
        with db.session.begin():
            transaction = Transaction.query.with_for_update().get(transaction_id)
            if transaction:
                if transaction.status != 'completed':
                    transaction.status = 'completed'
                    update_user_benefits(transaction.user_id, transaction_id)
            elif data["custom_data"].get("user_id"):
                transaction = Transaction(
                    id=transaction_id,
                    user_id=data['custom_data']['user_id'],
                    paddle_customer_id=data['customer_id'],
                    status='completed'
                )
                db.session.add(transaction)
            else:
                app.logger.error(f"handle_transaction_completed: Transaction not found for ID: {transaction_id}")
                return
    except IntegrityError:
        db.session.rollback()
        app.logger.error(f"handle_transaction_completed: Error processing transaction: {transaction_id}")
    except Exception as e:
        app.logger.error(f"handle_transaction_completed: Unexpected error processing transaction: {transaction_id}")
        app.logger.error(e)

def handle_transaction_canceled(data):
    try:
        transaction_id = data['id']
        with db.session.begin():
            transaction = Transaction.query.with_for_update().get(transaction_id)
            if transaction and transaction.status != 'canceled':
                transaction.status = 'canceled'
                if transaction.status == 'completed':
                    revert_user_benefits(transaction.user_id, transaction_id)
    except IntegrityError:
        db.session.rollback()
        app.logger.error(f"handle_transaction_canceled: Error processing transaction: {transaction_id}")
    except Exception as e:
        app.logger.error(f"handle_transaction_canceled: Unexpected error processing transaction: {transaction_id}")
        app.logger.error(e)

def update_user_benefits(user_id, transaction_id):
    user = User.query.get(user_id)
    if not user:
        app.logger.error(f"User not found for ID: {user_id}")
        return
    
    transaction = paddle.transactions.get(transaction_id)

    for item in transaction.items:
        product_id = item.price.product_id
        price_id = item.price.id
        if product_id in app.config['PADDLE_PRODUCTS'] and price_id in app.config['PADDLE_PRODUCTS'][product_id]['prices']:
            product_name = app.config['PADDLE_PRODUCTS'][product_id]['name']
            if product_name == 'subscription':
                user.upgrade_to_premium(transaction.subscription_id, months=app.config['PADDLE_PRODUCTS'][product_id]['prices'][price_id])
            elif product_name == 'extractions':
                user.paid_extractions_left += app.config['PADDLE_PRODUCTS'][item.price.product_id]['prices'][item.price.id]
    
    db.session.commit()

def revert_user_benefits(user_id, transaction_id):
    user = User.query.get(user_id)
    if not user:
        app.logger.error(f"User not found for ID: {user_id}")
        return
    
    transaction = paddle.transactions.get(transaction_id)

    for item in transaction.items:
        product_id = item.price.product_id
        price_id = item.price.id
        if product_id in app.config['PADDLE_PRODUCTS'] and price_id in app.config['PADDLE_PRODUCTS'][product_id]['prices']:
            product_name = app.config['PADDLE_PRODUCTS'][product_id]['name']
            if product_name == 'subscription':
                user.downgrade_to_free()
            elif product_name == 'extractions':
                user.paid_extractions_left -= app.config['PADDLE_PRODUCTS'][item.price.product_id]['prices'][item.price.id]
                if user.paid_extractions_left < 0:
                    user.paid_extractions_left = 0
    
    db.session.commit()

@app.route('/user_info', methods=['GET'])
def user_info():
    if 'user_id' not in session:
        raise Unauthorized('You must be logged in to view user info')

    user = User.query.get(session['user_id'])
    if user.is_premium and datetime.utcnow() > user.subscription_end:
        user.downgrade_to_free()
        db.session.commit()

    return jsonify({
        'id': user.id,
        'email': user.email,
        'tier': user.tier.value,
        'extractions_left': user.extractions_left,
        'paid_extractions_left': user.paid_extractions_left,
        'total_extractions': user.total_extractions,
        'reset_date': user.next_reset_date.isoformat(),
        'subscription_end': user.subscription_end.isoformat() if user.subscription_end else None,
        'subscription_next_billing': user.subscription_next_billing.isoformat() if user.subscription_next_billing else None,
        'is_premium': user.is_premium or user.is_dev
    })

@app.route('/after_request', methods=['POST'])
def after_request(response):
    logging.debug(f"Request method: {request.method}")
    logging.debug(f"Request path: {request.path}")
    logging.debug(f"Request headers: {request.headers}")
    logging.debug(f"Request from origin: {request.headers.get('Origin')}")
    logging.debug(f"CORS headers: {response.headers.get('Access-Control-Allow-Origin')}")
    return response

@app.errorhandler(BadRequest)
@app.errorhandler(Unauthorized)
@app.errorhandler(NotFound)
def handle_error(error):
    response = jsonify({'error': str(error)})
    response.status_code = error.code
    return response

@app.route('/verify_token', methods=['POST'])
def verify_token():
    token = request.json.get('token')
    token_record = Token.query.get(token)
    if not token_record or datetime.utcnow() > token_record.expiration:
        if token_record:
            db.session.delete(token_record)
            db.session.commit()
        logging.warning(f"Invalid or expired token: {token}")
        raise Forbidden('Invalid or expired token')
    user_id = token_record.user_id
    # db.session.delete(token_record)
    # db.session.commit()
    return jsonify({'user_id': user_id})

@app.route('/generate_payment_token', methods=['POST'])
def generate_payment_token():
    if 'user_id' not in session:
        raise Unauthorized('You must be logged in to generate a payment token')
    token = secrets.token_urlsafe()
    expiration = datetime.utcnow() + timedelta(minutes=5)
    new_token = Token(id=token, user_id=session['user_id'], expiration=expiration)
    db.session.add(new_token)
    db.session.commit()
    return jsonify({'token': token})

@app.route('/payments')
def payments():
    return send_from_directory('static', 'payments.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('/etc/ssl/certs/selfsigned.crt', '/etc/ssl/private/selfsigned.key'))
