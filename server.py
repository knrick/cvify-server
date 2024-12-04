# Python standard library imports
import base64
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from urllib.parse import urlparse
import shutil
import uuid

# Third-party imports
import requests
from dotenv import load_dotenv
from flask import (Flask, abort, jsonify, request, send_from_directory, session, render_template)
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from flask_apscheduler import APScheduler
from paddle_billing import Client, Environment, Options
from paddle_billing.Entities.Subscriptions import SubscriptionEffectiveFrom
from paddle_billing.Entities.Transactions import TransactionCreateItem
from paddle_billing.Resources.Prices import Operations as PriceOperations
from paddle_billing.Resources.Subscriptions import Operations as SubscriptionOperations
from paddle_billing.Resources.Transactions import Operations as TransactionOperations
from sqlalchemy import Enum as SQLAlchemyEnum, and_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload
import redis
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, Unauthorized
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Local imports
from utils.cv_jsoner import extract_structured_content, run_model
from utils.redis_helper import RedisHelper
from utils.rate_limiter import RateLimiter, RateLimits
from utils.cache import Cache, CacheTimeout

load_dotenv()

logging.basicConfig(filename='/var/log/cvify_app.log', level=logging.DEBUG)

static_folder = 'static'

app = Flask(__name__, static_url_path='', static_folder=static_folder)
CORS(
    app,
    supports_credentials=True,
    origins=['chrome-extension://*'],
    expose_headers=['Content-Type', 'X-CSRF-Token'],
    allow_headers=['Content-Type', 'X-CSRF-Token']
)

scheduler = APScheduler()

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cv_generator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Image configuration
app.config['PIC_FOLDER'] = 'profile_pictures'
app.config['PIC_UPLOAD_FOLDER'] = os.path.join(static_folder, app.config['PIC_FOLDER'])
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Paddle configuration
app.config['PADDLE_PRODUCTS'] = {
    os.getenv('EXTRACTIONS_PRODUCT_ID'): {
        'name': 'extractions',
        'prices': {
            os.getenv('SMALL_EXTRACTIONS_PRICE_ID'): 10,
            os.getenv('LARGE_EXTRACTIONS_PRICE_ID'): 50
        }
    },
    os.getenv('SUBSCRIPTION_PRODUCT_ID'): {
        'name': 'subscription',
        'prices': {
            os.getenv('MONTHLY_SUBSCRIPTION_PRICE_ID'): 1,
            os.getenv('YEARLY_SUBSCRIPTION_PRICE_ID'): 12
        }
    }
}

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('GMAIL_USERNAME')  # Your full Gmail address
app.config['MAIL_PASSWORD'] = os.getenv('GMAIL_APP_PASSWORD')  # The App Password generated above
app.config['MAIL_DEFAULT_SENDER'] = f'CVify (noreply) <{os.getenv("GMAIL_USERNAME")}>'

# WTF_CSRF configurations
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
app.config['WTF_CSRF_HEADERS'] = ['X-CSRF-Token']
app.config['WTF_CSRF_TIME_LIMIT'] = 1800

# Redis configurations
app.config['REDIS_HOST'] = os.getenv('REDIS_HOST')
app.config['REDIS_PORT'] = int(os.getenv('REDIS_PORT'))
app.config['REDIS_PASSWORD'] = os.getenv('REDIS_PASSWORD')
app.config['REDIS_DB'] = 0

# Scheduler configuration
app.config['SCHEDULER_API_ENABLED'] = True
app.config['SCHEDULER_TIMEZONE'] = 'UTC'

class DebugCSRFProtect(CSRFProtect):
    def validate_csrf(self, data, meta=None):
        if not data:
            logging.error("CSRF Validation Failed: No token provided in request")
            raise CSRFError("The CSRF token is missing.")

        if not self._get_csrf_token():
            logging.error("CSRF Validation Failed: No token stored in session")
            raise CSRFError("The CSRF session token is missing.")

        logging.info(f"CSRF Comparison:")
        logging.info(f"Token in request: {data}")
        logging.info(f"Token in session: {self._get_csrf_token()}")
        
        return super().validate_csrf(data, meta)

csrf = DebugCSRFProtect()
csrf.init_app(app)

@scheduler.task('interval', id='cleanup_rate_limits', seconds=3600, misfire_grace_time=900)
def cleanup_rate_limits():
    try:
        redis_client = RedisHelper.get_instance()
        pattern = "rate_limit:*"
        now = int(time.time())
        
        for key in redis_client.scan_iter(match=pattern):
            # Remove entries older than the window
            redis_client.zremrangebyscore(key, 0, now - 3600)  # 1 hour window
            
            # Delete key if empty
            if redis_client.zcard(key) == 0:
                redis_client.delete(key)
                
    except redis.RedisError as e:
        logging.error(f"Failed to cleanup rate limits: {str(e)}")

@scheduler.task('interval', id='cleanup_cache', hours=24)
def cleanup_cache():
    """Remove expired cache entries"""
    try:
        redis_client = RedisHelper.get_instance()
        
        # Scan for all keys
        for key in redis_client.scan_iter():
            # Check if key has TTL
            ttl = redis_client.ttl(key)
            if ttl < 0:  # No TTL set or expired
                redis_client.delete(key)
                
    except Exception as e:
        logging.error(f"Cache cleanup error: {str(e)}")

@scheduler.task('cron', id='cleanup_unverified_users', hour=0, minute=0, misfire_grace_time=3600)  # Run at midnight, 1 hour grace time
def cleanup_unverified_users():
    """Remove unverified users that are more than a week old"""
    try:
        # Calculate the cutoff date (1 week ago)
        cutoff_date = datetime.utcnow() - timedelta(weeks=1)
        
        # Find all unverified users with email verifications older than a week
        unverified_users = User.query.join(EmailVerification).filter(
            and_(
                User.email_verified == False,
                EmailVerification.created_at <= cutoff_date
            )
        ).all()

        # Return early if no unverified users found
        if not unverified_users:
            return
        
        # Delete associated records and users
        for user in unverified_users:
            # Delete associated email verifications
            EmailVerification.query.filter_by(user_id=user.id).delete()
            
            # Delete associated CVs and their profile pictures
            for cv in user.cvs:
                if cv.data.get('profile_picture'):
                    pic_path = os.path.join(app.config['PIC_UPLOAD_FOLDER'], os.path.basename(cv.data['profile_picture']))
                    if os.path.exists(pic_path):
                        os.remove(pic_path)
            
            # Delete the user
            db.session.delete(user)
        
        db.session.commit()
        logging.info(f"Cleaned up {len(unverified_users)} unverified users")
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error cleaning up unverified users: {str(e)}")

scheduler.init_app(app)
scheduler.start()


mail = Mail(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def download_and_save_image(image_url, update_filename=None):
    logging.debug(f"Starting download_and_save_image with url: {image_url}")
    if not image_url:
        logging.debug("No image URL provided")
        return None
    
    if update_filename:
        filename = update_filename
        logging.debug(f"Using update filename: {filename}")
    elif image_url.startswith('data:'):
        filename = "profile_picture.png"
        logging.debug("Using default profile picture filename for data URL")
    elif image_url.startswith(app.config['PIC_FOLDER']):
        filename = os.path.basename(image_url)
        image_url = os.path.join(app.config['PIC_UPLOAD_FOLDER'], filename)
    else:
        filename = secure_filename(os.path.basename(urlparse(image_url).path))
        logging.debug(f"Generated filename from URL: {filename}")
    
    # Create the directory if it doesn't exist
    try:
        os.makedirs(app.config['PIC_UPLOAD_FOLDER'], exist_ok=True)
        logging.debug(f"Created/verified upload directory: {app.config['PIC_UPLOAD_FOLDER']}")
    except Exception as e:
        logging.error(f"Failed to create upload directory: {str(e)}")
        return None
    
    def get_unique_filename(filename):
        store_filepath = os.path.join(app.config['PIC_UPLOAD_FOLDER'], filename)
        if update_filename is None:
            # Check for existing files and increment counter until we find an unused filename
            counter = 0
            base_name, extension = os.path.splitext(filename)
            while os.path.exists(store_filepath):
                counter += 1
                filename = f"{base_name}{counter}{extension}"
                store_filepath = os.path.join(app.config['PIC_UPLOAD_FOLDER'], filename)
                logging.debug(f"File exists, trying new filename: {filename}")
        download_filepath = os.path.join(app.config['PIC_FOLDER'], filename)

        return filename, store_filepath, download_filepath
    
    try:
        if image_url.startswith('data:'):
            logging.debug("Processing data URL image")
            filename, store_filepath, download_filepath = get_unique_filename(filename)
            with open(store_filepath, 'wb') as f:
                f.write(base64.b64decode(image_url.split(",")[1]))
        elif image_url.startswith(app.config['PIC_UPLOAD_FOLDER']):
            filename, store_filepath, download_filepath = get_unique_filename(filename)
            # Copy the file to the new location
            shutil.copy(image_url, store_filepath)
        else:
            logging.debug("Downloading image from URL")
            response = requests.get(image_url)
            if response.status_code != 200:
                logging.error(f"Failed to download image. Status code: {response.status_code}")
                return None
            
            # Get content type from response headers
            content_type = response.headers.get('content-type', '').lower()
            
            # Map content types to file extensions
            content_type_map = {
                'image/jpeg': '.jpg',
                'image/jpg': '.jpg', 
                'image/png': '.png',
                'image/gif': '.gif'
            }
            
            # Get appropriate extension or default to original
            extension = content_type_map.get(content_type)
            if extension:
                base_name = os.path.splitext(filename)[0]
                filename = base_name + extension
            
            filename, store_filepath, download_filepath = get_unique_filename(filename)
            
            if not allowed_file(filename):
                logging.error(f"File type not allowed: {filename}")
                return None
            
            with open(store_filepath, 'wb') as f:
                f.write(response.content)
                
        logging.debug(f"Successfully saved image to {store_filepath}")
        return download_filepath
        
    except Exception as e:
        logging.error(f"Failed to save image: {str(e)}")
        return None

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define models
class UserTier(Enum):
    FREE = 'free'
    PREMIUM = 'premium'
    DEV = 'dev'

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

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
            raise BadRequest('noExtractionsLeft')
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
                self.subscription_end = paddle_subscription.current_billing_period.ends_at if type(paddle_subscription.current_billing_period.ends_at) == datetime else datetime.fromisoformat(paddle_subscription.current_billing_period.ends_at.replace('Z', '+00:00'))
                self.subscription_next_billing = paddle_subscription.next_billed_at if type(paddle_subscription.next_billed_at) == datetime else datetime.fromisoformat(paddle_subscription.next_billed_at.replace('Z', '+00:00'))
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
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
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

class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

paddle = Client(os.getenv('PADDLE_API_KEY'), options=Options(environment=Environment.SANDBOX))

def send_verification_email(user_email, verification_code):
    try:
        msg = Message(
            'Verify your CVify account',
            recipients=[user_email]
        )
        msg.html = f'''
        <h1>Welcome to CVify!</h1>
        <p>Your verification code is: <strong>{verification_code}</strong></p>
        <p>This code will expire in 1 hour.</p>
        <p>If you didn't create an account with CVify, please ignore this email.</p>
        '''
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Error sending verification email: {str(e)}")
        return False

def send_password_reset_email(user_email, reset_code):
    try:
        msg = Message(
            'Reset your CVify password',
            recipients=[user_email]
        )
        msg.html = f'''
        <h1>Reset your CVify password</h1>
        <p>Your reset code is: <strong>{reset_code}</strong></p>
        <p>This code will expire in 1 hour.</p>
        <p>If you didn't request a password reset, please ignore this email.</p>
        '''
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Error sending password reset email: {str(e)}")
        return False

@app.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    response = jsonify({'token': token})
    response.headers.set('X-CSRF-Token', token)
    return response

@app.route('/health')
def health_check():
    try:
        redis_client = RedisHelper.get_instance()
        redis_client.ping()

        return jsonify({
            'status': 'healthy',
            'redis': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except redis.RedisError as e:
        return jsonify({
            'status': 'unhealthy',
            'redis': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
# THESE WILL BE ADDED WHEN ADMIN_REQUIRED IS IMPLEMENTED

# @app.route('/admin/redis-info')
# @admin_required
# def redis_info():
#     try:
#         redis_client = RedisHelper.get_instance()
#         info = redis_client.info()
        
#         return jsonify({
#             'used_memory': info['used_memory_human'],
#             'connected_clients': info['connected_clients'],
#             'uptime_days': info['uptime_in_days'],
#             'total_commands_processed': info['total_commands_processed'],
#             'total_connections_received': info['total_connections_received']
#         })
#     except redis.RedisError as e:
#         return jsonify({'error': str(e)}), 500

# @app.route('/admin/cache-info')
# @admin_required
# def cache_info():
#     try:
#         redis_client = RedisHelper.get_instance()
#         info = redis_client.info()
        
#         # Get cache statistics
#         cache_stats = {
#             'user_info': len(list(redis_client.scan_iter(match='user_info:*'))),
#             'cv': len(list(redis_client.scan_iter(match='cv:*'))),
#             'template': len(list(redis_client.scan_iter(match='template:*'))),
#         }
        
#         return jsonify({
#             'cache_stats': cache_stats,
#             'memory_used': info['used_memory_human'],
#             'hit_rate': info.get('keyspace_hits', 0) / (info.get('keyspace_hits', 0) + info.get('keyspace_misses', 1)),
#             'timestamp': datetime.utcnow().isoformat()
#         })
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.REGISTER)
def register():
    data = request.json

    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'emailAndPasswordRequired'}), 400

    # Email validation using the same regex pattern as in popup.js
    email_regex = re.compile(r'^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$', re.IGNORECASE)
    if not email_regex.match(data['email']):
        return jsonify({'message': 'invalidEmailMessage'}), 400

    # Password validation
    if len(data['password']) < 8 or not re.search(r'[a-zA-Z]', data['password']) or not re.search(r'[0-9]', data['password']):
        return jsonify({'message': 'invalidPasswordMessage'}), 400

    email = data['email'].lower()
    
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'userAlreadyExistsMessage'}), 400

    try:
        new_user = User(
            email=email,
            email_verified=False,
            next_reset_date=datetime.utcnow() + timedelta(days=30)
        )
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.flush()  # Get the user ID without committing

        # Generate verification code
        verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        verification = EmailVerification(
            user_id=new_user.id,
            code=verification_code,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(verification)
        db.session.commit()

        # Send verification email
        if send_verification_email(email, verification_code):
            return jsonify({
                'message': 'userCreatedMessage',
                'requiresVerification': True
            }), 201
        else:
            return jsonify({'message': 'errorSendingVerificationEmail'}), 500

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in registration: {str(e)}")
        return jsonify({'message': 'errorCreatingUser'}), 500

@app.route('/verify-email', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.VERIFY_EMAIL)
def verify_email():
    data = request.json
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({'message': 'emailAndVerificationCodeRequired'}), 400

    email = email.lower()

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'userNotFound'}), 404

    user_id = user.id
    verification = EmailVerification.query.filter_by(
        user_id=user_id,
        code=code
    ).first()

    if not verification or verification.expires_at < datetime.utcnow():
        return jsonify({'message': 'invalidOrExpiredVerificationCode'}), 400

    try:
        user.email_verified = True
        db.session.delete(verification)
        db.session.commit()
        Cache.invalidate_user_info_cache(user_id)
        session["user_id"] = user_id
        return jsonify({'message': 'emailVerifiedSuccessfully'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error verifying email: {str(e)}")
        return jsonify({'message': 'errorVerifyingEmail'}), 500

@app.route('/resend-verification', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.RESEND_VERIFICATION)
def resend_verification():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'emailRequired'}), 400
    
    email = email.lower()

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'userNotFound'}), 404

    if user.email_verified:
        return jsonify({'message': 'emailAlreadyVerified'}), 400

    try:
        # Delete any existing verification codes
        EmailVerification.query.filter_by(user_id=user.id).delete()

        # Generate new verification code
        verification_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        verification = EmailVerification(
            user_id=user.id,
            code=verification_code,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(verification)
        db.session.commit()

        # Send verification email
        if send_verification_email(user.email, verification_code):
            return jsonify({'message': 'verificationEmailSent'}), 200
        else:
            return jsonify({'message': 'errorSendingVerificationEmail'}), 500

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resending verification: {str(e)}")
        return jsonify({'message': 'errorResendingVerification'}), 500

@app.route('/request-password-reset', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.REQUEST_PASSWORD_RESET)
def request_password_reset():
    data = request.json
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'userNotFound'}), 404
    
    email = email.lower()
    
    reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    reset = PasswordReset(
        user_id=user.id,
        code=reset_code,
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    db.session.add(reset)
    db.session.commit()

    if send_password_reset_email(user.email, reset_code):
        return jsonify({'message': 'passwordResetEmailSent'}), 200
    else:
        return jsonify({'message': 'errorSendingPasswordResetEmail'}), 500

@app.route('/reset-password', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.RESET_PASSWORD)
def reset_password():
    data = request.json
    email = data.get('email')
    code = data.get('code')
    password = data.get('password')

    if not email or not code or not password:
        return jsonify({'message': 'emailCodeAndPasswordRequired'}), 400
    
    email = email.lower()
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'userNotFound'}), 404
    
    reset = PasswordReset.query.filter_by(
        user_id=user.id,
        code=code
    ).first()

    if not reset or reset.expires_at < datetime.utcnow():
        return jsonify({'message': 'invalidOrExpiredResetCode'}), 400
    
    user.set_password(password)
    db.session.delete(reset)
    db.session.commit()

    return jsonify({'message': 'passwordResetSuccessfully'}), 200

@app.route('/resend-password-reset', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.RESEND_PASSWORD_RESET)
def resend_password_reset():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'emailRequired'}), 400

    email = email.lower()

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'userNotFound'}), 404

    try:
        # Delete any existing password reset codes
        PasswordReset.query.filter_by(user_id=user.id).delete()

        # Generate new verification code
        reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        reset = PasswordReset(
            user_id=user.id,
            code=reset_code,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(reset)
        db.session.commit()

        # Send verification email
        if send_password_reset_email(user.email, reset_code):
            return jsonify({'message': 'passwordResetEmailSent'}), 200
        else:
            return jsonify({'message': 'errorSendingPasswordResetEmail'}), 500

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resending password reset: {str(e)}")
        return jsonify({'message': 'errorResendingPasswordReset'}), 500

@app.route('/cancel-password-reset', methods=['POST'])
def cancel_password_reset():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'message': 'emailRequired'}), 400
    
    email = email.lower()

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'userNotFound'}), 404

    try:
        # Delete any existing password reset codes
        PasswordReset.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        return jsonify({'message': 'passwordResetCancelled'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error cancelling password reset: {str(e)}")
        return jsonify({'message': 'errorCancellingPasswordReset'}), 500

@app.route('/login', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.LOGIN)
def login():
    data = request.get_json()
    logging.debug(f"Login attempt for user: {data.get('email')}")

    email = data['email'].lower()

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(data['password']):
        session['user_id'] = user.id
        logging.debug(f"User {user.id} logged in successfully")
        return jsonify({'message': 'loggedInSuccessfully'}), 200
    logging.debug("Login failed")
    return jsonify({'message': 'invalidUsernameOrPassword'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'loggedOutSuccessfully'}), 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/refund')
def refund():
    return render_template('refund.html')

@app.route('/process', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.PROCESS)
def process_html():
    if 'user_id' not in session:
        raise Unauthorized('unauthorized')
    
    user = User.query.get(session['user_id'])
    if not user:
        raise Unauthorized('unauthorized')
    if not user.can_extract:
        raise BadRequest('noExtractionsLeft')
    
    if user.tier == UserTier.FREE:
        if len(user.cvs) >= 2:
            raise BadRequest('freeTierCVLimit')

    html = request.json['html']
    source_url = request.json.get('source_url')

    try:

        structured_content = extract_structured_content(html, False)
        cv_data = run_model(structured_content)

        if 'profile_picture' in cv_data:
            local_image_path = download_and_save_image(cv_data['profile_picture'])
            if local_image_path is None:
                del cv_data['profile_picture']
            else:
                cv_data['profile_picture'] = local_image_path
    except Exception as e:
        app.logger.error(f"Error processing HTML: {str(e)}")
        return jsonify({'error': 'An error occurred while processing the HTML'}), 500

    name = f"{cv_data.get('name', 'Unnamed')} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    new_cv = CV(user=user, data=cv_data, source_url=source_url, name=name)
    
    try:
        db.session.add(new_cv)
        user.deduct_extraction()
        db.session.commit()
        Cache.invalidate_user_cache(session['user_id'])
    except SQLAlchemyError as e:
        db.session.rollback()
        if local_image_path:
            os.remove(local_image_path)
        app.logger.error(f"Database error in process_html: {str(e)}")

    return jsonify({'message': 'cvProcessedSuccessfully'}), 200

@app.route('/user-cvs', methods=['GET'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
@Cache.cached('user_cvs', timeout=CacheTimeout.MEDIUM_SHORT) # 15 minutes
def get_user_cvs():
    if 'user_id' not in session:
        logging.debug("User not in session")
        return jsonify({'message': 'unauthorized'}), 401
    
    user = User.query.get(session['user_id'])
    cvs = [{'id': cv.id, 'name': cv.name, 'created_at': cv.created_at.isoformat()} for cv in user.cvs]
    return jsonify(cvs)

@app.route('/cv/<cv_id>', methods=['GET'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
@Cache.cached('cv', timeout=CacheTimeout.MEDIUM) # 1 hour
def get_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    
    cv = CV.query.get_or_404(cv_id)
    if cv.user_id != session['user_id']:
        return jsonify({'message': 'Unauthorized'}), 401
    
    return jsonify(cv.data)

@app.route('/cv/<cv_id>/delete', methods=['DELETE'])
@RateLimiter.rate_limit(**RateLimits.DELETE_CV)
def delete_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    
    cv = CV.query.get_or_404(cv_id)
    if cv.user_id != session['user_id']:
        return jsonify({'message': 'Unauthorized'}), 401
    
    db.session.delete(cv)
    db.session.commit()
    logging.debug(f"Successfully deleted CV {cv_id} for user {session['user_id']}")
    Cache.invalidate_user_cv_cache(cv_id, session['user_id'])

    if cv.data.get('profile_picture'):
        pic_path = os.path.join(app.config['PIC_UPLOAD_FOLDER'], os.path.basename(cv.data['profile_picture']))
        if os.path.exists(pic_path):
            os.remove(pic_path)
    
    return jsonify({'message': 'cvDeletedSuccessfully'}), 200

@app.route('/create-cv', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.CREATE_CV)
def create_cv():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    
    user = User.query.get(session['user_id'])

    if user.tier == UserTier.FREE:
        if len(user.cvs) >= 2:
            raise BadRequest('freeTierCVLimit')
    
    cv_data = request.json
    
    # Generate a name for the new CV
    cv_name = f"New CV - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    
    new_cv = CV(user=user, data=cv_data, name=cv_name)
    db.session.add(new_cv)
    db.session.commit()
    Cache.invalidate_user_cvs_cache(session['user_id'])
    
    return jsonify({'message': 'cvCreatedSuccessfully', 'id': new_cv.id}), 201

@app.route('/cv/<cv_id>/update', methods=['PUT'])
@RateLimiter.rate_limit(**RateLimits.UPDATE_CV)
def update_cv(cv_id):
    logging.debug(f"Starting update_cv for cv_id: {cv_id}")

    if 'user_id' not in session:
        logging.debug("User not in session, returning unauthorized")
        return jsonify({'message': 'unauthorized'}), 401
    
    logging.debug(f"Looking up CV with id {cv_id}")
    cv = CV.query.get_or_404(cv_id)
    
    if cv.user_id != session['user_id']:
        logging.debug(f"CV user_id {cv.user_id} does not match session user_id {session['user_id']}")
        return jsonify({'message': 'unauthorized'}), 401
    
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
        Cache.invalidate_cv_cache(cv_id)
    except Exception as e:
        logging.error(f"Error updating CV: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while updating the CV'}), 500
    
    logging.debug("CV updated successfully")
    return jsonify({'message': 'cvUpdatedSuccessfully'}), 200

@app.route('/cv/<cv_id>/rename', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.RENAME_CV)
def rename_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'message': 'unauthorized'}), 401
    
    try:
        new_name = request.json.get('name')
        if not new_name or not isinstance(new_name, str):
            raise BadRequest('newNameRequiredAndMustBeString')
        
        if len(new_name) > 200:  # Assuming max length of 200 characters
            raise BadRequest('newNameTooLong')
        
        cv = CV.query.get(cv_id)
        if not cv:
            raise NotFound('cvNotFound')
        
        if cv.user_id != session['user_id']:
            raise Unauthorized('youDoNotHavePermissionToRenameThisCV')
        
        cv.name = new_name
        db.session.commit()
        Cache.invalidate_user_cvs_cache(session['user_id'])
        
        return jsonify({'message': 'cvRenamedSuccessfully'}), 200
    
    except BadRequest as e:
        return jsonify({'message': str(e)}), 400
    except Unauthorized as e:
        return jsonify({'message': str(e)}), 401
    except NotFound as e:
        return jsonify({'message': str(e)}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error while renaming CV: {str(e)}")
        return jsonify({'message': 'anErrorOccurredWhileRenamingTheCV'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error while renaming CV: {str(e)}")
        return jsonify({'message': 'anUnexpectedErrorOccurred'}), 500

@app.route('/cv/<cv_id>/duplicate', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.DUPLICATE_CV)
def duplicate_cv(cv_id):
    if 'user_id' not in session:
        return jsonify({'message': 'unauthorized'}), 401
    
    try:
        original_cv = CV.query.get(cv_id)
        if not original_cv:
            raise NotFound('cvNotFound')
        
        if original_cv.user_id != session['user_id']:
            raise Unauthorized('youDoNotHavePermissionToDuplicateThisCV')
        
        # Check if user has reached maximum allowed CVs (e.g., 10)
        user_cv_count = CV.query.filter_by(user_id=session['user_id']).count()
        if user_cv_count >= 10:
            raise BadRequest('youHaveReachedTheMaximumNumberOfAllowedCVs')
        
        new_name = f"{original_cv.name} (Copy)"
        if len(new_name) > 200:
            new_name = new_name[:197] + "..."
        
        # Copy the CV data
        cv_data = original_cv.data.copy()
        
        # If there's a profile picture, create a copy of it
        if cv_data.get('profile_picture'):
            # Create a copy of the profile picture file
            original_path = cv_data['profile_picture']
            if os.path.exists(os.path.join(static_folder, original_path)):
                new_path = download_and_save_image(original_path)
                if new_path:
                    cv_data['profile_picture'] = new_path
            
        new_cv = CV(
            name=new_name,
            data=cv_data,
            user_id=session['user_id']
        )
        db.session.add(new_cv)
        db.session.commit()
        Cache.invalidate_user_cvs_cache(session['user_id'])
        
        return jsonify({'message': 'cvDuplicatedSuccessfully', 'id': new_cv.id}), 201
    
    except BadRequest as e:
        return jsonify({'message': str(e)}), 400
    except Unauthorized as e:
        return jsonify({'message': str(e)}), 401
    except NotFound as e:
        return jsonify({'message': str(e)}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error while duplicating CV: {str(e)}")
        return jsonify({'message': 'errorDuplicatingCV'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error while duplicating CV: {str(e)}")
        return jsonify({'message': 'anUnexpectedErrorOccurred'}), 500

@app.route('/initiate-transaction', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
def initiate_transaction():
    if 'user_id' not in session:
        return jsonify({'message': 'unauthorized'}), 401

    data = request.json
    user_id = session['user_id']

    if user_id != data['userId']:
        return jsonify({'message': 'userIDMismatch'}), 401

    # Check if transaction already exists
    existing_transaction = Transaction.query.get(data['transactionId'])
    if existing_transaction:
        if existing_transaction.user_id != user_id:
            return jsonify({'message': 'transactionExistsButBelongsToDifferentUser'}), 401
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
            return jsonify({'message': 'transactionExistsButBelongsToDifferentUser'}), 401
        return jsonify({'transactionId': existing_transaction.id}), 200

    return jsonify({'transactionId': new_transaction.id}), 200

@app.route('/confirm-transaction', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
def confirm_transaction():
    if 'user_id' not in session:
        return jsonify({'message': 'unauthorized'}), 401

    data = request.json
    user_id = session['user_id']

    try:
        # Use a database transaction to ensure atomicity
        with db.session.begin():
            transaction = Transaction.query.with_for_update().get(data['transactionId'])
            if not transaction:
                return jsonify({'message': 'transactionNotFound'}), 404
            
            if transaction.user_id != user_id:
                return jsonify({'message': 'userIDMismatch'}), 401
            
            if transaction.status == 'completed':
                return jsonify({'message': 'transactionAlreadyCompleted'}), 200

            transaction.status = 'completed'
            update_user_benefits(user_id, data['transactionId'])

        return jsonify({'message': 'Transaction confirmed'}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'transactionError'}), 500

@app.route('/cancel-subscription', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
def cancel_subscription():
    if 'user_id' not in session:
        raise Unauthorized('youMustBeLoggedInToCancelASubscription')

    user = User.query.get(session['user_id'])

    if not user:
        raise BadRequest('invalidUser')
    
    if user.is_dev:
        try:
            paddle.subscriptions.cancel(
                user.subscription_id,
                SubscriptionOperations.CancelSubscription(
                    SubscriptionEffectiveFrom("immediately")
                )
            )
            return jsonify({'message': 'subscriptionCancelledSuccessfully'}), 200
        except Exception as e:
            app.logger.error(f"Error cancelling subscription: {str(e)}")
            return jsonify({'message': 'failedToCancelSubscription'}), 500
    
    elif user.is_premium:
        try:
            paddle.subscriptions.cancel(
                user.subscription_id,
                SubscriptionOperations.CancelSubscription()
            )
            user.subscription_next_billing = None
            db.session.commit()
            Cache.invalidate_user_info_cache(session['user_id'])
            return jsonify({'message': 'subscriptionCancelledSuccessfully'}), 200
        except Exception as e:
            app.logger.error(f"Error cancelling subscription: {str(e)}")
            return jsonify({'message': 'failedToCancelSubscription'}), 500
    else:
        return jsonify({'message': 'notPremiumUser'}), 403

@app.route('/webhook', methods=['POST'])
@csrf.exempt
def webhook():
    try:
        notification = request.json

        logging.info(f"logging.info: Received webhook: {notification}")
        app.logger.info(f"app.logger.info: Received webhook: {notification}")
        
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
        Cache.invalidate_user_info_cache(user_id)
    else:
        app.logger.error(f"handle_subscription_created: User not found for ID: {user_id}")

def handle_subscription_updated(data):
    user = User.query.filter_by(subscription_id=data['id']).first()
    if user:
        user_id = user.id
        user.subscription_end = datetime.fromisoformat(data['current_billing_period']['ends_at'].replace('Z', '+00:00'))
        user.subscription_next_billing = datetime.fromisoformat(data['next_billed_at'].replace('Z', '+00:00'))
        if not user.is_premium and user.subscription_end > datetime.utcnow():
            user.tier = UserTier.PREMIUM
        db.session.commit()
        Cache.invalidate_user_info_cache(user_id)
    else:
        app.logger.error(f"handle_subscription_updated: User not found for subscription: {data['id']}")

def handle_subscription_canceled(data):
    user = User.query.filter_by(subscription_id=data['id']).first()
    if user:
        user_id = user.id
        user.downgrade_to_free()
        db.session.commit()
        Cache.invalidate_user_info_cache(user_id)
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
    Cache.invalidate_user_info_cache(user_id)

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
    Cache.invalidate_user_info_cache(user_id)

@app.route('/user-info', methods=['GET'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
@Cache.cached('user_info', timeout=CacheTimeout.SHORT) # 5 minutes
def user_info():
    if 'user_id' not in session:
        raise Unauthorized('youMustBeLoggedInToViewUserInfo')

    user = User.query.get(session['user_id'])
    if user.is_premium and datetime.utcnow() > user.subscription_end:
        user.downgrade_to_free()
        db.session.commit()
        Cache.invalidate_user_info_cache(session['user_id'])

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
        'is_premium': user.is_premium or user.is_dev,
        'email_verified': user.email_verified
    })

@app.errorhandler(BadRequest)
@app.errorhandler(Unauthorized)
@app.errorhandler(NotFound)
def handle_error(error):
    response = jsonify({'error': str(error)})
    response.status_code = error.code
    return response

# Add error handler for rate limit exceeded
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'message': 'rateLimitExceeded',
        'message': str(e.description)
    }), 429

@app.route('/verify-token', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
def verify_token():
    token = request.json.get('token')
    token_record = Token.query.get(token)
    if not token_record or datetime.utcnow() > token_record.expiration:
        if token_record:
            db.session.delete(token_record)
            db.session.commit()
        logging.warning(f"Invalid or expired token: {token}")
        raise Forbidden('invalidOrExpiredToken')
    user_id = token_record.user_id
    return jsonify({'user_id': user_id})

@app.route('/generate-payment-token', methods=['POST'])
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
def generate_payment_token():
    if 'user_id' not in session:
        raise Unauthorized('youMustBeLoggedInToGenerateAPaymentToken')
    token = secrets.token_urlsafe()
    expiration = datetime.utcnow() + timedelta(minutes=5)
    new_token = Token(id=token, user_id=session['user_id'], expiration=expiration)
    db.session.add(new_token)
    db.session.commit()
    return jsonify({'token': token})

@app.route('/payments')
@RateLimiter.rate_limit(**RateLimits.DEFAULT)
@csrf.exempt
def payments():
    return send_from_directory('static', 'payments_placeholder.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('/etc/ssl/certs/selfsigned.crt', '/etc/ssl/private/selfsigned.key'))
