# complete_bot.py
import os
import json
import uuid
import time
import random
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
import re
from urllib.parse import urlparse
import requests

# Telegram Bot
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup,
    ReplyKeyboardMarkup, KeyboardButton, WebAppInfo
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)
from telegram.constants import ParseMode

# Firebase
import firebase_admin
from firebase_admin import credentials, firestore, db
import pytz

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================

class Config:
    BOT_TOKEN = "8384600981:AAFOkWJEw0zPqouHrwFUYw9LI7m-eLBp1KE"
    
    # Firebase Configuration
    FIREBASE_CONFIG = {
        "apiKey": "AIzaSyABekPzR4zxlY8rws16hyYNmFlMXBcggXk",
        "authDomain": "vansh-98953.firebaseapp.com",
        "databaseURL": "https://vansh-98953-default-rtdb.firebaseio.com",
        "projectId": "vansh-98953",
        "storageBucket": "vansh-98953.firebasestorage.app",
        "messagingSenderId": "784796743834",
        "appId": "1:784796743834:web:b4ca65fc00f6ce50ff0723",
        "measurementId": "G-V4037GN0ZB"
    }
    
    # Admin IDs (replace with your Telegram user ID)
    ADMIN_IDS = [1234567890]  # Add your Telegram user ID here
    
    # Commission Settings
    REFERRAL_COMMISSION = 10  # 10% lifetime commission
    WITHDRAWAL_MIN_UPI = 50
    WITHDRAWAL_MIN_BANK = 50
    WITHDRAWAL_MIN_CRYPTO = 200
    AD_COMMISSION = 10  # 10% commission on ads
    
    # Security
    ENCRYPTION_KEY = "vansh_bot_security_key_2024_secure"
    MAX_DAILY_WITHDRAWAL = 5000
    COOLDOWN_SECONDS = 30

# ==================== FIREBASE SETUP ====================

class Database:
    def __init__(self):
        try:
            # Initialize Firebase with Realtime Database
            cred = credentials.Certificate(self._create_temp_credentials())
            firebase_admin.initialize_app(cred, {
                'databaseURL': Config.FIREBASE_CONFIG['databaseURL']
            })
            self.db = db.reference()
            logger.info("Firebase initialized successfully")
        except Exception as e:
            logger.error(f"Firebase initialization error: {e}")
            raise e
    
    def _create_temp_credentials(self):
        """Create temporary credentials file"""
        cred_data = {
            "type": "service_account",
            "project_id": Config.FIREBASE_CONFIG['projectId'],
            "private_key_id": "temp_key_id",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cK\n-----END PRIVATE KEY-----\n",
            "client_email": f"firebase-adminsdk@{Config.FIREBASE_CONFIG['projectId']}.iam.gserviceaccount.com",
            "client_id": "123456789",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk%40{Config.FIREBASE_CONFIG['projectId']}.iam.gserviceaccount.com"
        }
        with open('temp_credentials.json', 'w') as f:
            json.dump(cred_data, f)
        return 'temp_credentials.json'
    
    # ============ USER MANAGEMENT ============
    
    def create_user(self, user_data: dict) -> bool:
        """Create new user"""
        try:
            user_id = str(user_data['user_id'])
            user_ref = self.db.child('users').child(user_id)
            
            # Check if user exists
            if user_ref.get():
                return False
            
            # Generate unique referral code
            referral_code = hashlib.md5(user_id.encode()).hexdigest()[:8].upper()
            
            user_info = {
                'user_id': user_id,
                'username': user_data.get('username', ''),
                'first_name': user_data.get('first_name', ''),
                'last_name': user_data.get('last_name', ''),
                'referral_code': referral_code,
                'referred_by': user_data.get('referred_by', None),
                'referrals': [],
                'total_referrals': 0,
                'referral_earnings': 0.0,
                'is_banned': False,
                'is_active': True,
                'created_at': self._get_timestamp(),
                'last_active': self._get_timestamp(),
                'completed_tasks': [],
                'completed_visits': [],
                'shortened_links': []
            }
            
            user_ref.set(user_info)
            
            # Create wallet for user
            self._create_wallet(user_id)
            
            # Handle referral
            if user_data.get('referred_by'):
                self._process_referral(user_data['referred_by'], user_id)
            
            logger.info(f"User created: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False
    
    def get_user(self, user_id: str) -> dict:
        """Get user data"""
        try:
            user_ref = self.db.child('users').child(str(user_id))
            return user_ref.get() or {}
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return {}
    
    def update_user(self, user_id: str, data: dict) -> bool:
        """Update user data"""
        try:
            user_ref = self.db.child('users').child(str(user_id))
            user_ref.update(data)
            return True
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            return False
    
    def _create_wallet(self, user_id: str) -> bool:
        """Create wallet for user"""
        try:
            wallet_ref = self.db.child('wallets').child(str(user_id))
            wallet_data = {
                'user_id': user_id,
                'balance': 0.0,
                'total_earned': 0.0,
                'total_withdrawn': 0.0,
                'pending_withdrawal': 0.0,
                'created_at': self._get_timestamp(),
                'updated_at': self._get_timestamp()
            }
            wallet_ref.set(wallet_data)
            logger.info(f"Wallet created for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Error creating wallet: {e}")
            return False
    
    def get_wallet(self, user_id: str) -> dict:
        """Get wallet data"""
        try:
            wallet_ref = self.db.child('wallets').child(str(user_id))
            return wallet_ref.get() or {}
        except Exception as e:
            logger.error(f"Error getting wallet: {e}")
            return {}
    
    def update_balance(self, user_id: str, amount: float, transaction_type: str = 'credit') -> bool:
        """Update wallet balance"""
        try:
            wallet_ref = self.db.child('wallets').child(str(user_id))
            wallet = wallet_ref.get()
            
            if not wallet:
                self._create_wallet(user_id)
                wallet = wallet_ref.get()
            
            current_balance = float(wallet.get('balance', 0))
            total_earned = float(wallet.get('total_earned', 0))
            total_withdrawn = float(wallet.get('total_withdrawn', 0))
            
            if transaction_type == 'credit':
                new_balance = current_balance + amount
                new_total_earned = total_earned + amount
                wallet_ref.update({
                    'balance': new_balance,
                    'total_earned': new_total_earned,
                    'updated_at': self._get_timestamp()
                })
            else:  # debit/withdrawal
                if current_balance < amount:
                    return False
                new_balance = current_balance - amount
                new_total_withdrawn = total_withdrawn + amount
                wallet_ref.update({
                    'balance': new_balance,
                    'total_withdrawn': new_total_withdrawn,
                    'updated_at': self._get_timestamp()
                })
            
            # Log transaction
            self._log_transaction(user_id, amount, transaction_type)
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating balance: {e}")
            return False
    
    def _log_transaction(self, user_id: str, amount: float, transaction_type: str):
        """Log transaction"""
        try:
            transaction_ref = self.db.child('transactions').push()
            transaction_data = {
                'user_id': user_id,
                'amount': amount,
                'type': transaction_type,
                'timestamp': self._get_timestamp()
            }
            transaction_ref.set(transaction_data)
        except Exception as e:
            logger.error(f"Error logging transaction: {e}")
    
    # ============ REFERRAL SYSTEM ============
    
    def _process_referral(self, referrer_code: str, new_user_id: str) -> bool:
        """Process referral - find referrer by code and add referral"""
        try:
            # Find referrer by referral code
            users_ref = self.db.child('users')
            all_users = users_ref.get()
            
            referrer_id = None
            if all_users:
                for uid, user_data in all_users.items():
                    if user_data.get('referral_code') == referrer_code:
                        referrer_id = uid
                        break
            
            if not referrer_id or referrer_id == new_user_id:
                return False
            
            # Add referral to referrer
            referrer_ref = self.db.child('users').child(referrer_id)
            referrer_data = referrer_ref.get()
            
            if referrer_data:
                referrals = referrer_data.get('referrals', [])
                if new_user_id not in referrals:
                    referrals.append(new_user_id)
                    referrer_ref.update({
                        'referrals': referrals,
                        'total_referrals': len(referrals)
                    })
                
                # Create referral record
                referral_record = {
                    'referrer_id': referrer_id,
                    'referred_id': new_user_id,
                    'total_commission': 0.0,
                    'created_at': self._get_timestamp(),
                    'status': 'active'
                }
                self.db.child('referrals').push(referral_record)
                
                logger.info(f"Referral processed: {referrer_id} referred {new_user_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error processing referral: {e}")
            return False
    
    def add_referral_commission(self, referred_id: str, amount: float) -> bool:
        """Add lifetime commission to referrer"""
        try:
            # Find referrer of this user
            referrals_ref = self.db.child('referrals')
            all_referrals = referrals_ref.get()
            
            if not all_referrals:
                return False
            
            referrer_id = None
            referral_key = None
            for key, ref_data in all_referrals.items():
                if ref_data.get('referred_id') == str(referred_id):
                    referrer_id = ref_data.get('referrer_id')
                    referral_key = key
                    break
            
            if not referrer_id:
                return False
            
            # Calculate commission (10%)
            commission = round(amount * Config.REFERRAL_COMMISSION / 100, 2)
            
            if commission <= 0:
                return False
            
            # Add to referrer's balance
            self.update_balance(referrer_id, commission, 'credit')
            
            # Update referral earnings
            user_ref = self.db.child('users').child(referrer_id)
            user_data = user_ref.get()
            if user_data:
                current_earning = float(user_data.get('referral_earnings', 0))
                user_ref.update({'referral_earnings': current_earning + commission})
            
            # Update referral record
            if referral_key:
                ref_record_ref = self.db.child('referrals').child(referral_key)
                ref_record = ref_record_ref.get()
                if ref_record:
                    total_commission = float(ref_record.get('total_commission', 0)) + commission
                    ref_record_ref.update({'total_commission': total_commission})
            
            logger.info(f"Referral commission added: {commission} to {referrer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding referral commission: {e}")
            return False
    
    # ============ WITHDRAWAL SYSTEM ============
    
    def create_withdrawal(self, user_id: str, amount: float, method: str, details: dict) -> str:
        """Create withdrawal request"""
        try:
            withdrawal_id = f"WD{int(time.time())}{random.randint(100, 999)}"
            
            withdrawal_data = {
                'withdrawal_id': withdrawal_id,
                'user_id': str(user_id),
                'amount': amount,
                'method': method,  # 'upi', 'bank', 'crypto'
                'details': details,
                'status': 'pending',
                'created_at': self._get_timestamp(),
                'processed_at': None,
                'transaction_id': None,
                'admin_note': ''
            }
            
            withdrawal_ref = self.db.child('withdrawals').child(withdrawal_id)
            withdrawal_ref.set(withdrawal_data)
            
            # Update pending withdrawal
            wallet_ref = self.db.child('wallets').child(str(user_id))
            wallet = wallet_ref.get()
            if wallet:
                pending = float(wallet.get('pending_withdrawal', 0)) + amount
                wallet_ref.update({'pending_withdrawal': pending})
            
            logger.info(f"Withdrawal created: {withdrawal_id}")
            return withdrawal_id
            
        except Exception as e:
            logger.error(f"Error creating withdrawal: {e}")
            return None
    
    def get_pending_withdrawals(self, user_id: str = None) -> list:
        """Get pending withdrawals"""
        try:
            withdrawals_ref = self.db.child('withdrawals')
            
            if user_id:
                # Get specific user's withdrawals
                all_withdrawals = withdrawals_ref.get()
                if not all_withdrawals:
                    return []
                return [
                    {**wd, 'id': wid} 
                    for wid, wd in all_withdrawals.items() 
                    if wd.get('user_id') == str(user_id)
                ]
            else:
                # Get all pending withdrawals for admin
                all_withdrawals = withdrawals_ref.get()
                if not all_withdrawals:
                    return []
                return [
                    {**wd, 'id': wid} 
                    for wid, wd in all_withdrawals.items() 
                    if wd.get('status') == 'pending'
                ]
        except Exception as e:
            logger.error(f"Error getting withdrawals: {e}")
            return []
    
    # ============ TASK SYSTEM ============
    
    def create_task(self, task_data: dict) -> str:
        """Create a new task (admin function)"""
        try:
            task_ref = self.db.child('tasks').push()
            task_info = {
                'title': task_data.get('title', ''),
                'description': task_data.get('description', ''),
                'reward': float(task_data.get('reward', 0)),
                'url': task_data.get('url', ''),
                'instructions': task_data.get('instructions', ''),
                'is_active': True,
                'created_at': self._get_timestamp(),
                'completed_count': 0,
                'daily_limit': int(task_data.get('daily_limit', 0)),
                'time_required': int(task_data.get('time_required', 60))  # seconds
            }
            task_ref.set(task_info)
            return task_ref.key
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            return None
    
    def get_available_tasks(self, user_id: str) -> list:
        """Get available tasks for a user"""
        try:
            tasks_ref = self.db.child('tasks')
            tasks = tasks_ref.get()
            
            if not tasks:
                return []
            
            user_data = self.get_user(user_id)
            completed_tasks = user_data.get('completed_tasks', [])
            
            available_tasks = []
            for task_id, task_data in tasks.items():
                if task_data.get('is_active') and task_id not in completed_tasks:
                    task_data['task_id'] = task_id
                    available_tasks.append(task_data)
            
            return available_tasks
        except Exception as e:
            logger.error(f"Error getting tasks: {e}")
            return []
    
    def complete_task(self, user_id: str, task_id: str) -> bool:
        """Mark task as completed"""
        try:
            task_ref = self.db.child('tasks').child(task_id)
            task = task_ref.get()
            
            if not task:
                return False
            
            reward = float(task.get('reward', 0))
            
            # Add to user's completed tasks
            user_ref = self.db.child('users').child(str(user_id))
            user_data = user_ref.get()
            completed_tasks = user_data.get('completed_tasks', [])
            
            if task_id in completed_tasks:
                return False
            
            completed_tasks.append(task_id)
            user_ref.update({'completed_tasks': completed_tasks})
            
            # Update task completion count
            completed_count = int(task.get('completed_count', 0)) + 1
            task_ref.update({'completed_count': completed_count})
            
            # Add reward to wallet
            self.update_balance(user_id, reward, 'credit')
            
            # Add referral commission
            self.add_referral_commission(user_id, reward)
            
            logger.info(f"Task completed: {task_id} by {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error completing task: {e}")
            return False
    
    # ============ ADVERTISEMENT SYSTEM ============
    
    def create_advertisement(self, user_id: str, ad_data: dict) -> str:
        """Create advertisement request"""
        try:
            # Check if user has enough balance
            wallet = self.get_wallet(user_id)
            amount = float(ad_data.get('amount', 0))
            
            if float(wallet.get('balance', 0)) < amount:
                return None
            
            # Deduct amount from wallet
            self.update_balance(user_id, amount, 'debit')
            
            # Add commission (10%)
            commission = round(amount * Config.AD_COMMISSION / 100, 2)
            
            ad_ref = self.db.child('advertisements').push()
            ad_info = {
                'user_id': str(user_id),
                'title': ad_data.get('title', ''),
                'description': ad_data.get('description', ''),
                'url': ad_data.get('url', ''),
                'amount': amount,
                'commission': commission,
                'status': 'pending',
                'created_at': self._get_timestamp(),
                'approved_at': None,
                'views': 0,
                'clicks': 0,
                'total_spent': amount,
                'is_active': False
            }
            ad_ref.set(ad_info)
            
            logger.info(f"Advertisement created: {ad_ref.key}")
            return ad_ref.key
            
        except Exception as e:
            logger.error(f"Error creating advertisement: {e}")
            return None
    
    def get_active_ads(self) -> list:
        """Get approved and active advertisements"""
        try:
            ads_ref = self.db.child('advertisements')
            all_ads = ads_ref.get()
            
            if not all_ads:
                return []
            
            active_ads = [
                {**ad, 'ad_id': ad_id}
                for ad_id, ad in all_ads.items()
                if ad.get('status') == 'approved' and ad.get('is_active')
            ]
            
            return active_ads
        except Exception as e:
            logger.error(f"Error getting ads: {e}")
            return []
    
    def record_ad_view(self, ad_id: str, viewer_id: str) -> float:
        """Record advertisement view and pay viewer"""
        try:
            ad_ref = self.db.child('advertisements').child(ad_id)
            ad = ad_ref.get()
            
            if not ad:
                return 0
            
            # Calculate reward per view (small amount)
            reward = round(random.uniform(0.01, 0.05), 2)
            
            # Update ad views
            views = int(ad.get('views', 0)) + 1
            ad_ref.update({'views': views})
            
            # Add reward to viewer
            self.update_balance(viewer_id, reward, 'credit')
            
            return reward
            
        except Exception as e:
            logger.error(f"Error recording ad view: {e}")
            return 0
    
    # ============ LINK SHORTENER ============
    
    def create_short_link(self, user_id: str, original_url: str) -> dict:
        """Create shortened link"""
        try:
            # Generate short code
            short_code = hashlib.md5(f"{user_id}{original_url}{time.time()}".encode()).hexdigest()[:6]
            
            short_link_data = {
                'user_id': str(user_id),
                'original_url': original_url,
                'short_code': short_code,
                'short_url': f"https://short.vansh.in/{short_code}",
                'clicks': 0,
                'earnings': 0.0,
                'created_at': self._get_timestamp(),
                'is_active': True
            }
            
            link_ref = self.db.child('short_links').child(short_code)
            link_ref.set(short_link_data)
            
            # Update user's links
            user_ref = self.db.child('users').child(str(user_id))
            user_data = user_ref.get()
            shortened_links = user_data.get('shortened_links', [])
            shortened_links.append(short_code)
            user_ref.update({'shortened_links': shortened_links})
            
            return short_link_data
            
        except Exception as e:
            logger.error(f"Error creating short link: {e}")
            return None
    
    def process_short_link_click(self, short_code: str, visitor_ip: str = None) -> dict:
        """Process click on shortened link"""
        try:
            link_ref = self.db.child('short_links').child(short_code)
            link_data = link_ref.get()
            
            if not link_data or not link_data.get('is_active'):
                return None
            
            # Update click count
            clicks = int(link_data.get('clicks', 0)) + 1
            link_ref.update({'clicks': clicks})
            
            # Calculate earnings per click
            earning_per_click = 0.002  # ₹0.002 per click
            earnings = float(link_data.get('earnings', 0)) + earning_per_click
            
            link_ref.update({'earnings': earnings})
            
            # Add to user's balance
            user_id = link_data.get('user_id')
            self.update_balance(user_id, earning_per_click, 'credit')
            
            # Add referral commission
            self.add_referral_commission(user_id, earning_per_click)
            
            return {
                'original_url': link_data.get('original_url'),
                'earnings': earning_per_click
            }
            
        except Exception as e:
            logger.error(f"Error processing link click: {e}")
            return None
    
    # ============ VISIT TO EARN ============
    
    def create_visit_task(self, visit_data: dict) -> str:
        """Create visit to earn task (admin)"""
        try:
            visit_ref = self.db.child('visit_tasks').push()
            visit_info = {
                'title': visit_data.get('title', ''),
                'url': visit_data.get('url', ''),
                'reward': float(visit_data.get('reward', 0)),
                'duration': int(visit_data.get('duration', 30)),  # seconds to stay
                'is_active': True,
                'created_at': self._get_timestamp(),
                'total_visits': 0
            }
            visit_ref.set(visit_info)
            return visit_ref.key
        except Exception as e:
            logger.error(f"Error creating visit task: {e}")
            return None
    
    def complete_visit(self, user_id: str, visit_id: str) -> bool:
        """Complete visit to earn task"""
        try:
            visit_ref = self.db.child('visit_tasks').child(visit_id)
            visit = visit_ref.get()
            
            if not visit or not visit.get('is_active'):
                return False
            
            user_data = self.get_user(user_id)
            completed_visits = user_data.get('completed_visits', [])
            
            if visit_id in completed_visits:
                return False
            
            reward = float(visit.get('reward', 0))
            
            # Update completed visits
            completed_visits.append(visit_id)
            self.update_user(user_id, {'completed_visits': completed_visits})
            
            # Update visit count
            total_visits = int(visit.get('total_visits', 0)) + 1
            visit_ref.update({'total_visits': total_visits})
            
            # Add reward
            self.update_balance(user_id, reward, 'credit')
            
            # Add referral commission
            self.add_referral_commission(user_id, reward)
            
            return True
            
        except Exception as e:
            logger.error(f"Error completing visit: {e}")
            return False
    
    # ============ UTILITY FUNCTIONS ============
    
    def _get_timestamp(self):
        """Get current timestamp"""
        return {'.sv': 'timestamp'}
    
    def is_user_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        return user_id in Config.ADMIN_IDS
    
    def get_bot_stats(self) -> dict:
        """Get bot statistics"""
        try:
            users_ref = self.db.child('users')
            users = users_ref.get()
            total_users = len(users) if users else 0
            
            wallets_ref = self.db.child('wallets')
            wallets = wallets_ref.get()
            
            total_balance = 0
            if wallets:
                total_balance = sum(float(w.get('balance', 0)) for w in wallets.values())
            
            withdrawals_ref = self.db.child('withdrawals')
            withdrawals = withdrawals_ref.get()
            pending_withdrawals = len([w for w in (withdrawals or {}).values() if w.get('status') == 'pending'])
            
            return {
                'total_users': total_users,
                'total_balance': total_balance,
                'pending_withdrawals': pending_withdrawals,
                'timestamp': time.time()
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {}

# Initialize database
db_manager = Database()

# ==================== KEYBOARDS ====================

def get_main_menu_keyboard():
    """Main menu keyboard"""
    keyboard = [
        [InlineKeyboardButton("💰 Wallet", callback_data="wallet")],
        [InlineKeyboardButton("📋 Tasks", callback_data="tasks"),
         InlineKeyboardButton("👁️ Visit to Earn", callback_data="visit")],
        [InlineKeyboardButton("🔗 Link Shortner", callback_data="shortner"),
         InlineKeyboardButton("👥 Referral", callback_data="referral")],
        [InlineKeyboardButton("📢 Advertisement", callback_data="advertisement")],
        [InlineKeyboardButton("ℹ️ Help & Support", callback_data="help")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_wallet_keyboard():
    """Wallet menu keyboard"""
    keyboard = [
        [InlineKeyboardButton("💳 Withdraw", callback_data="withdraw")],
        [InlineKeyboardButton("📊 Transaction History", callback_data="history")],
        [InlineKeyboardButton("🔙 Back to Menu", callback_data="back_to_menu")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_withdrawal_methods_keyboard():
    """Withdrawal methods keyboard"""
    keyboard = [
        [InlineKeyboardButton("📱 UPI", callback_data="withdraw_upi")],
        [InlineKeyboardButton("🏦 Bank Transfer", callback_data="withdraw_bank")],
        [InlineKeyboardButton("₿ Crypto (BTC/USDT)", callback_data="withdraw_crypto")],
        [InlineKeyboardButton("🔙 Back", callback_data="wallet")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_admin_keyboard():
    """Admin panel keyboard"""
    keyboard = [
        [InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")],
        [InlineKeyboardButton("➕ Add Task", callback_data="admin_add_task")],
        [InlineKeyboardButton("👁️ Add Visit Task", callback_data="admin_add_visit")],
        [InlineKeyboardButton("💸 Pending Withdrawals", callback_data="admin_withdrawals")],
        [InlineKeyboardButton("📢 Manage Ads", callback_data="admin_ads")],
        [InlineKeyboardButton("👥 User Management", callback_data="admin_users")],
        [InlineKeyboardButton("📤 Broadcast", callback_data="admin_broadcast")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
    ]
    return InlineKeyboardMarkup(keyboard)

# ==================== HANDLERS ====================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command handler"""
    user = update.effective_user
    user_id = user.id
    
    # Check for referral code
    referral_code = None
    if context.args and len(context.args) > 0:
        referral_code = context.args[0]
    
    # Create or get user
    user_data = db_manager.get_user(str(user_id))
    
    if not user_data:
        # Create new user
        new_user = {
            'user_id': str(user_id),
            'username': user.username or '',
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'referred_by': referral_code
        }
        
        if db_manager.create_user(new_user):
            user_data = db_manager.get_user(str(user_id))
            
            # Welcome message for new user
            welcome_message = f"""
🎉 *Welcome to Vansh Earning Bot!* 🎉

Hello {user.first_name}! 

Your account has been created successfully!

📱 *Your Details:*
• User ID: `{user_id}`
• Referral Code: `{user_data.get('referral_code', 'N/A')}`

🎁 *Earning Opportunities:*
• Complete Tasks
• Visit Websites
• Short Links
• Refer Friends (10% Lifetime Commission)
• View Advertisements

💰 *Join Bonus: ₹5 credited to your wallet!*

Start earning now! 🚀
"""
            # Give joining bonus
            db_manager.update_balance(str(user_id), 5.0, 'credit')
            
        else:
            welcome_message = "❌ Error creating account. Please try again later."
    else:
        if user_data.get('is_banned'):
            await update.message.reply_text("❌ Your account has been banned. Contact support.")
            return
        
        welcome_message = f"""
👋 *Welcome Back, {user.first_name}!*

📊 *Your Stats:*
• Balance: ₹{db_manager.get_wallet(str(user_id)).get('balance', 0):.2f}
• Referrals: {user_data.get('total_referrals', 0)}
• Tasks Completed: {len(user_data.get('completed_tasks', []))}

Use the menu below to start earning! 💰
"""
    
    # Update last active
    db_manager.update_user(str(user_id), {'last_active': {'.sv': 'timestamp'}})
    
    await update.message.reply_text(
        welcome_message,
        reply_markup=get_main_menu_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all button callbacks"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    data = query.data
    
    # Check if user exists and not banned
    user_data = db_manager.get_user(str(user_id))
    if not user_data:
        await query.edit_message_text("❌ Please use /start first!")
        return
    
    if user_data.get('is_banned'):
        await query.edit_message_text("❌ Your account has been banned.")
        return
    
    # Route to appropriate handler
    if data == "wallet":
        await wallet_handler(query, user_id)
    elif data == "withdraw":
        await withdraw_menu(query, user_id)
    elif data in ["withdraw_upi", "withdraw_bank", "withdraw_crypto"]:
        await process_withdrawal(query, user_id, data)
    elif data == "history":
        await transaction_history(query, user_id)
    elif data == "tasks":
        await tasks_handler(query, user_id)
    elif data == "visit":
        await visit_handler(query, user_id)
    elif data == "shortner":
        await shortner_handler(query, user_id)
    elif data == "referral":
        await referral_handler(query, user_id)
    elif data == "advertisement":
        await advertisement_handler(query, user_id)
    elif data == "help":
        await help_handler(query, user_id)
    elif data == "back_to_menu":
        await back_to_menu(query, user_id)
    elif data.startswith("task_"):
        task_id = data.replace("task_", "")
        await complete_task(query, user_id, task_id)
    elif data.startswith("visit_"):
        visit_id = data.replace("visit_", "")
        await complete_visit_task(query, user_id, visit_id)
    elif data.startswith("admin_"):
        if db_manager.is_user_admin(user_id):
            await admin_handler(query, user_id, data)
        else:
            await query.edit_message_text("❌ Unauthorized access!")
    elif data.startswith("ad_view_"):
        ad_id = data.replace("ad_view_", "")
        await view_ad(query, user_id, ad_id)

# ============ WALLET FUNCTIONS ============

async def wallet_handler(query, user_id):
    """Display wallet information"""
    wallet = db_manager.get_wallet(str(user_id))
    user = db_manager.get_user(str(user_id))
    
    balance = float(wallet.get('balance', 0))
    total_earned = float(wallet.get('total_earned', 0))
    total_withdrawn = float(wallet.get('total_withdrawn', 0))
    pending = float(wallet.get('pending_withdrawal', 0))
    
    message = f"""
💰 *Your Wallet*

💵 *Balance:* ₹{balance:.2f}
📈 *Total Earned:* ₹{total_earned:.2f}
💸 *Total Withdrawn:* ₹{total_withdrawn:.2f}
⏳ *Pending Withdrawal:* ₹{pending:.2f}

🔹 *Referral Earnings:* ₹{float(user.get('referral_earnings', 0)):.2f}
👥 *Total Referrals:* {user.get('total_referrals', 0)}

💳 *Withdrawal Limits:*
• UPI: Min ₹{Config.WITHDRAWAL_MIN_UPI}
• Bank: Min ₹{Config.WITHDRAWAL_MIN_BANK}
• Crypto: Min ₹{Config.WITHDRAWAL_MIN_CRYPTO}
"""
    
    await query.edit_message_text(
        message,
        reply_markup=get_wallet_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

async def withdraw_menu(query, user_id):
    """Show withdrawal options"""
    wallet = db_manager.get_wallet(str(user_id))
    balance = float(wallet.get('balance', 0))
    
    if balance < Config.WITHDRAWAL_MIN_UPI:
        await query.edit_message_text(
            f"❌ Minimum balance required: ₹{Config.WITHDRAWAL_MIN_UPI}\nYour balance: ₹{balance:.2f}",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="wallet")
            ]])
        )
        return
    
    message = f"""
💳 *Withdraw Funds*

Your Balance: ₹{balance:.2f}

Select withdrawal method:

📱 *UPI:* Min ₹{Config.WITHDRAWAL_MIN_UPI}
🏦 *Bank:* Min ₹{Config.WITHDRAWAL_MIN_BANK}
₿ *Crypto:* Min ₹{Config.WITHDRAWAL_MIN_CRYPTO}
"""
    
    await query.edit_message_text(
        message,
        reply_markup=get_withdrawal_methods_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

async def process_withdrawal(query, user_id, method):
    """Process withdrawal request"""
    wallet = db_manager.get_wallet(str(user_id))
    balance = float(wallet.get('balance', 0))
    
    # Store withdrawal method in context
    context = query.message.chat.id
    context.user_data['withdrawal_method'] = method
    
    method_names = {
        'withdraw_upi': 'UPI',
        'withdraw_bank': 'Bank Transfer',
        'withdraw_crypto': 'Crypto (BTC/USDT)'
    }
    
    min_amounts = {
        'withdraw_upi': Config.WITHDRAWAL_MIN_UPI,
        'withdraw_bank': Config.WITHDRAWAL_MIN_BANK,
        'withdraw_crypto': Config.WITHDRAWAL_MIN_CRYPTO
    }
    
    method_name = method_names.get(method, 'Unknown')
    min_amount = min_amounts.get(method, 50)
    
    if balance < min_amount:
        await query.edit_message_text(
            f"❌ For {method_name}, minimum withdrawal is ₹{min_amount}\nYour balance: ₹{balance:.2f}",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="withdraw")
            ]])
        )
        return
    
    message = f"""
💳 *{method_name} Withdrawal*

Your Balance: ₹{balance:.2f}
Minimum: ₹{min_amount}

Please enter the amount you want to withdraw:

{get_withdrawal_instructions(method)}
"""
    
    await query.edit_message_text(
        message,
        parse_mode=ParseMode.MARKDOWN
    )

def get_withdrawal_instructions(method):
    """Get withdrawal instructions based on method"""
    if method == 'withdraw_upi':
        return "Format: `AMOUNT UPI_ID`\nExample: `100 user@upi`"
    elif method == 'withdraw_bank':
        return "Format: `AMOUNT ACCOUNT_NUMBER IFSC_CODE`\nExample: `100 12345678901 ABCD0123456`"
    elif method == 'withdraw_crypto':
        return "Format: `AMOUNT CRYPTO_TYPE ADDRESS`\nExample: `500 BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`"

async def transaction_history(query, user_id):
    """Show transaction history"""
    # Get recent transactions from Firebase
    transactions = db_manager.get_pending_withdrawals(str(user_id))
    
    if not transactions:
        message = "📊 *No transactions found*"
    else:
        message = "📊 *Recent Transactions*\n\n"
        for tx in transactions[:10]:  # Last 10 transactions
            message += f"• ID: {tx.get('id', 'N/A')[:10]}...\n"
            message += f"  Amount: ₹{tx.get('amount', 0)}\n"
            message += f"  Status: {tx.get('status', 'N/A')}\n\n"
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Back", callback_data="wallet")
        ]]),
        parse_mode=ParseMode.MARKDOWN
    )

# ============ TASK FUNCTIONS ============

async def tasks_handler(query, user_id):
    """Show available tasks"""
    tasks = db_manager.get_available_tasks(str(user_id))
    
    if not tasks:
        message = """
📋 *Tasks*

No tasks available right now. Check back later!

💡 Complete tasks to earn money!
"""
        await query.edit_message_text(
            message,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")
            ]]),
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    message = "📋 *Available Tasks*\n\n"
    keyboard = []
    
    for task in tasks[:5]:  # Show 5 tasks at a time
        message += f"• *{task.get('title', 'Task')}*\n"
        message += f"  💰 Reward: ₹{task.get('reward', 0)}\n"
        message += f"  {task.get('description', '')}\n\n"
        
        keyboard.append([InlineKeyboardButton(
            f"✅ {task.get('title', 'Complete')} - ₹{task.get('reward', 0)}",
            callback_data=f"task_{task.get('task_id')}"
        )])
    
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")])
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode=ParseMode.MARKDOWN
    )

async def complete_task(query, user_id, task_id):
    """Complete a task"""
    success = db_manager.complete_task(str(user_id), task_id)
    
    if success:
        # Get updated balance
        wallet = db_manager.get_wallet(str(user_id))
        
        message = f"""
✅ *Task Completed Successfully!*

💰 Reward added to your wallet!

Current Balance: ₹{float(wallet.get('balance', 0)):.2f}
"""
        await query.edit_message_text(
            message,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("📋 More Tasks", callback_data="tasks"),
                InlineKeyboardButton("🔙 Menu", callback_data="back_to_menu")
            ]]),
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await query.edit_message_text(
            "❌ Failed to complete task. Please try again.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="tasks")
            ]])
        )

# ============ VISIT TO EARN ============

async def visit_handler(query, user_id):
    """Show visit to earn opportunities"""
    # Get visit tasks from Firebase
    visits_ref = db_manager.db.child('visit_tasks')
    visits = visits_ref.get()
    
    if not visits:
        # Create sample visit task if none exist
        sample_visit = {
            'title': 'Visit Website',
            'url': 'https://example.com',
            'reward': 2.0,
            'duration': 30,
            'is_active': True,
            'created_at': {'.sv': 'timestamp'},
            'total_visits': 0
        }
        visits_ref.push(sample_visit)
        visits = visits_ref.get()
    
    user_data = db_manager.get_user(str(user_id))
    completed_visits = user_data.get('completed_visits', [])
    
    message = "👁️ *Visit to Earn*\n\nEarn money by visiting websites!\n\n"
    keyboard = []
    
    for visit_id, visit in visits.items():
        if visit.get('is_active') and visit_id not in completed_visits:
            message += f"• *{visit.get('title')}*\n"
            message += f"  💰 Reward: ₹{visit.get('reward', 0)}\n"
            message += f"  ⏱️ Duration: {visit.get('duration', 30)} seconds\n\n"
            
            keyboard.append([InlineKeyboardButton(
                f"👁️ {visit.get('title')} - ₹{visit.get('reward', 0)}",
                callback_data=f"visit_{visit_id}"
            )])
    
    if not keyboard:
        message += "No new visits available. Check back later!"
    
    keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")])
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode=ParseMode.MARKDOWN
    )

async def complete_visit_task(query, user_id, visit_id):
    """Complete a visit task"""
    success = db_manager.complete_visit(str(user_id), visit_id)
    
    if success:
        wallet = db_manager.get_wallet(str(user_id))
        
        message = f"""
✅ *Visit Completed!*

💰 Reward added to your wallet!

Current Balance: ₹{float(wallet.get('balance', 0)):.2f}

⚠️ Remember: You must stay on the website for the required time!
"""
        await query.edit_message_text(
            message,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("👁️ More Visits", callback_data="visit"),
                InlineKeyboardButton("🔙 Menu", callback_data="back_to_menu")
            ]]),
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await query.edit_message_text(
            "❌ Failed to complete visit. Please try again.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="visit")
            ]])
        )

# ============ LINK SHORTNER ============

async def shortner_handler(query, user_id):
    """Handle link shortner"""
    message = """
🔗 *Link Shortner*

Earn money by shortening and sharing links!

💰 *How it works:*
1. Send any URL to shorten
2. Get your shortened link
3. Share with others
4. Earn ₹0.002 per click!

📤 Send your URL now to get started!
"""
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")
        ]]),
        parse_mode=ParseMode.MARKDOWN
    )

# ============ REFERRAL SYSTEM ============

async def referral_handler(query, user_id):
    """Handle referral system"""
    user_data = db_manager.get_user(str(user_id))
    referral_code = user_data.get('referral_code', '')
    total_referrals = user_data.get('total_referrals', 0)
    referral_earnings = float(user_data.get('referral_earnings', 0))
    referrals = user_data.get('referrals', [])
    
    bot_username = (await query.message.bot.get_me()).username
    referral_link = f"https://t.me/{bot_username}?start={referral_code}"
    
    message = f"""
👥 *Referral Program*

🎁 Earn *10% Lifetime Commission* on every referral's earnings!

📱 *Your Referral Code:* `{referral_code}`
🔗 *Your Referral Link:*
`{referral_link}`

📊 *Your Stats:*
• Total Referrals: {total_referrals}
• Referral Earnings: ₹{referral_earnings:.2f}

💡 *How it works:*
1. Share your referral link
2. Friends join using your link
3. You earn 10% of their lifetime earnings
4. Unlimited referrals!

📤 Share your link now and start earning!
"""
    
    keyboard = [
        [InlineKeyboardButton("📤 Share Referral Link", switch_inline_query=f"Join and earn money! {referral_link}")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")]
    ]
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode=ParseMode.MARKDOWN
    )

# ============ ADVERTISEMENT ============

async def advertisement_handler(query, user_id):
    """Handle advertisements"""
    active_ads = db_manager.get_active_ads()
    
    if not active_ads:
        message = """
📢 *Advertisements*

No ads available to view right now.

*Create Your Own Ad:*
📤 Promote your product/service here!
💰 Cost: ₹10 + 10% commission

To create an ad, send:
`/advertise AMOUNT TITLE | DESCRIPTION | URL`
"""
    else:
        message = "📢 *View Ads and Earn!*\n\n"
        keyboard = []
        
        for ad in active_ads[:3]:
            message += f"• {ad.get('title', 'Ad')}\n"
            message += f"  {ad.get('description', '')}\n\n"
            
            keyboard.append([InlineKeyboardButton(
                f"👁️ View & Earn ₹0.02-0.05",
                callback_data=f"ad_view_{ad.get('ad_id')}"
            )])
        
        message += "\n💡 *Create Your Ad:* `/advertise`"
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")])
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup(keyboard if active_ads else [[
            InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")
        ]]),
        parse_mode=ParseMode.MARKDOWN
    )

async def view_ad(query, user_id, ad_id):
    """View an advertisement"""
    reward = db_manager.record_ad_view(ad_id, str(user_id))
    
    if reward > 0:
        wallet = db_manager.get_wallet(str(user_id))
        message = f"""
✅ *Ad Viewed!*

💰 Earned: ₹{reward:.2f}
💵 Balance: ₹{float(wallet.get('balance', 0)):.2f}

View more ads to earn more!
"""
    else:
        message = "❌ Failed to process ad view. Please try again."
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("📢 More Ads", callback_data="advertisement"),
            InlineKeyboardButton("🔙 Menu", callback_data="back_to_menu")
        ]]),
        parse_mode=ParseMode.MARKDOWN
    )

# ============ HELP ============

async def help_handler(query, user_id):
    """Help and support"""
    message = """
ℹ️ *Help & Support*

📋 *Available Commands:*
/start - Start the bot
/balance - Check balance
/withdraw - Withdraw earnings
/tasks - View tasks
/referral - Get referral link
/advertise - Create advertisement
/help - Show this help

💡 *Earning Methods:*
1. Complete Tasks
2. Visit Websites
3. Shorten Links (₹0.002/click)
4. Refer Friends (10% lifetime commission)
5. View Ads

💰 *Withdrawal:*
• UPI: Min ₹50
• Bank: Min ₹50
• Crypto: Min ₹200

⚠️ *Support:*
Contact admin for issues and queries.
"""
    
    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")
        ]]),
        parse_mode=ParseMode.MARKDOWN
    )

async def back_to_menu(query, user_id):
    """Return to main menu"""
    wallet = db_manager.get_wallet(str(user_id))
    
    message = f"""
🎯 *Main Menu*

Welcome back! 
💰 Balance: ₹{float(wallet.get('balance', 0)):.2f}

Select an option to start earning:
"""
    
    await query.edit_message_text(
        message,
        reply_markup=get_main_menu_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

# ============ ADMIN FUNCTIONS ============

async def admin_handler(query, user_id, data):
    """Admin panel handler"""
    if not db_manager.is_user_admin(user_id):
        await query.edit_message_text("❌ Unauthorized!")
        return
    
    if data == "admin_stats":
        stats = db_manager.get_bot_stats()
        
        message = f"""
📊 *Bot Statistics*

👥 Total Users: {stats.get('total_users', 0)}
💰 Total Balance: ₹{stats.get('total_balance', 0):.2f}
⏳ Pending Withdrawals: {stats.get('pending_withdrawals', 0)}
🕐 Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        await query.edit_message_text(
            message,
            reply_markup=get_admin_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == "admin_withdrawals":
        pending = db_manager.get_pending_withdrawals()
        
        if not pending:
            message = "✅ No pending withdrawals!"
        else:
            message = f"💸 *Pending Withdrawals* ({len(pending)})\n\n"
            for wd in pending[:10]:
                message += f"• ID: {wd.get('id', 'N/A')[:10]}...\n"
                message += f"  User: {wd.get('user_id', 'N/A')}\n"
                message += f"  Amount: ₹{wd.get('amount', 0)}\n"
                message += f"  Method: {wd.get('method', 'N/A')}\n\n"
        
        await query.edit_message_text(
            message,
            reply_markup=get_admin_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == "admin_add_task":
        await query.edit_message_text(
            "➕ *Add Task*\n\nFormat:\n`/addtask TITLE | DESCRIPTION | REWARD | URL`",
            reply_markup=get_admin_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == "admin_broadcast":
        await query.edit_message_text(
            "📤 *Broadcast Message*\n\nSend message to all users:\n`/broadcast YOUR MESSAGE`",
            reply_markup=get_admin_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )

# ============ MESSAGE HANDLERS ============

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages"""
    user_id = update.effective_user.id
    message_text = update.message.text
    
    # Check if user is processing withdrawal
    if 'withdrawal_method' in context.user_data:
        await handle_withdrawal_message(update, context)
        return
    
    # Handle link shortening
    if message_text.startswith('http://') or message_text.startswith('https://'):
        await handle_link_shortening(update, context)
        return
    
    # Default response
    await update.message.reply_text(
        "Please use the buttons below to navigate:",
        reply_markup=get_main_menu_keyboard()
    )

async def handle_withdrawal_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle withdrawal details input"""
    user_id = str(update.effective_user.id)
    method = context.user_data.get('withdrawal_method')
    message_text = update.message.text
    
    if not method:
        await update.message.reply_text("❌ Session expired. Please try again.")
        del context.user_data['withdrawal_method']
        return
    
    wallet = db_manager.get_wallet(user_id)
    balance = float(wallet.get('balance', 0))
    
    # Parse withdrawal details based on method
    parts = message_text.split()
    
    if method == 'withdraw_upi':
        if len(parts) < 2:
            await update.message.reply_text(
                "❌ Invalid format!\nUse: `AMOUNT UPI_ID`\nExample: `100 user@upi`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        try:
            amount = float(parts[0])
            upi_id = parts[1]
        except:
            await update.message.reply_text("❌ Invalid amount!")
            return
        
        if not re.match(r'^[\w\.\-]+@[\w\-]+$', upi_id):
            await update.message.reply_text("❌ Invalid UPI ID!")
            return
        
        min_amount = Config.WITHDRAWAL_MIN_UPI
        
    elif method == 'withdraw_bank':
        if len(parts) < 3:
            await update.message.reply_text(
                "❌ Invalid format!\nUse: `AMOUNT ACCOUNT IFSC`\nExample: `100 12345678901 ABCD0123456`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        try:
            amount = float(parts[0])
            account = parts[1]
            ifsc = parts[2]
        except:
            await update.message.reply_text("❌ Invalid amount!")
            return
        
        min_amount = Config.WITHDRAWAL_MIN_BANK
        
    elif method == 'withdraw_crypto':
        if len(parts) < 3:
            await update.message.reply_text(
                "❌ Invalid format!\nUse: `AMOUNT CRYPTO ADDRESS`\nExample: `500 BTC 1A1zP1...`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        try:
            amount = float(parts[0])
            crypto_type = parts[1].upper()
            address = parts[2]
        except:
            await update.message.reply_text("❌ Invalid amount!")
            return
        
        if crypto_type not in ['BTC', 'USDT']:
            await update.message.reply_text("❌ Supported crypto: BTC, USDT")
            return
        
        min_amount = Config.WITHDRAWAL_MIN_CRYPTO
    
    # Validate amount
    if amount < min_amount:
        await update.message.reply_text(
            f"❌ Minimum withdrawal amount is ₹{min_amount}"
        )
        return
    
    if amount > balance:
        await update.message.reply_text(
            f"❌ Insufficient balance! Your balance: ₹{balance:.2f}"
        )
        return
    
    # Create withdrawal request
    details = {
        'amount': amount,
        'method': method.replace('withdraw_', '')
    }
    
    if method == 'withdraw_upi':
        details['upi_id'] = upi_id
    elif method == 'withdraw_bank':
        details['account'] = account
        details['ifsc'] = ifsc
    elif method == 'withdraw_crypto':
        details['crypto_type'] = crypto_type
        details['address'] = address
    
    withdrawal_id = db_manager.create_withdrawal(
        user_id, amount, method.replace('withdraw_', ''), details
    )
    
    if withdrawal_id:
        # Update wallet balance
        db_manager.update_balance(user_id, amount, 'debit')
        
        await update.message.reply_text(
            f"""
✅ *Withdrawal Request Created!*

📋 *Request ID:* `{withdrawal_id}`
💰 *Amount:* ₹{amount:.2f}
📱 *Method:* {method.replace('withdraw_', '').upper()}

⏳ Your withdrawal will be processed within 24-48 hours.
📊 Check status in Wallet > Transaction History
""",
            reply_markup=get_main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text(
            "❌ Failed to create withdrawal. Please try again."
        )
    
    # Clear withdrawal session
    del context.user_data['withdrawal_method']

async def handle_link_shortening(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle link shortening"""
    user_id = str(update.effective_user.id)
    url = update.message.text
    
    # Validate URL
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL")
    except:
        await update.message.reply_text("❌ Invalid URL! Please send a valid URL.")
        return
    
    # Create short link
    short_link = db_manager.create_short_link(user_id, url)
    
    if short_link:
        message = f"""
🔗 *Link Shortened!*

📤 *Original:* {url}
🔗 *Short Link:* `{short_link['short_url']}`

💰 Earn ₹0.002 per click on your link!
📊 Track earnings in your wallet.

Share this link to start earning!
"""
        await update.message.reply_text(
            message,
            reply_markup=get_main_menu_keyboard(),
            parse_mode=ParseMode.MARKDOWN
        )
    else:
        await update.message.reply_text("❌ Failed to shorten link. Please try again.")

# ============ COMMAND HANDLERS ============

async def balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check balance command"""
    user_id = update.effective_user.id
    wallet = db_manager.get_wallet(str(user_id))
    
    await update.message.reply_text(
        f"💰 Your Balance: ₹{float(wallet.get('balance', 0)):.2f}"
    )

async def withdraw_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Withdraw command"""
    user_id = update.effective_user.id
    wallet = db_manager.get_wallet(str(user_id))
    
    message = f"""
💳 *Withdraw Funds*

Your Balance: ₹{float(wallet.get('balance', 0)):.2f}

Select method:
"""
    
    await update.message.reply_text(
        message,
        reply_markup=get_withdrawal_methods_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

async def advertise_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Create advertisement command"""
    user_id = update.effective_user.id
    
    # Parse arguments
    args = context.args
    if not args:
        await update.message.reply_text(
            "📢 *Create Ad*\n\nFormat: `/advertise AMOUNT TITLE | DESCRIPTION | URL`\n\nExample: `/advertise 50 My Product | Best product ever | https://example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    # Process advertisement
    await update.message.reply_text(
        "📢 Advertisement feature: Send `/advertise AMOUNT TITLE | DESCRIPTION | URL` to create your ad. Cost = Amount + 10% commission."
    )

async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin panel command"""
    user_id = update.effective_user.id
    
    if not db_manager.is_user_admin(user_id):
        await update.message.reply_text("❌ Unauthorized!")
        return
    
    await update.message.reply_text(
        "🔐 *Admin Panel*",
        reply_markup=get_admin_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

async def add_task_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Add task command (admin)"""
    user_id = update.effective_user.id
    
    if not db_manager.is_user_admin(user_id):
        await update.message.reply_text("❌ Unauthorized!")
        return
    
    message_text = update.message.text.replace('/addtask ', '')
    parts = message_text.split('|')
    
    if len(parts) < 4:
        await update.message.reply_text(
            "❌ Format: `/addtask TITLE | DESCRIPTION | REWARD | URL`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    task_data = {
        'title': parts[0].strip(),
        'description': parts[1].strip(),
        'reward': float(parts[2].strip()),
        'url': parts[3].strip(),
        'is_active': True
    }
    
    task_id = db_manager.create_task(task_data)
    
    if task_id:
        await update.message.reply_text(f"✅ Task created successfully! ID: `{task_id}`", parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text("❌ Failed to create task.")

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Broadcast message to all users (admin)"""
    user_id = update.effective_user.id
    
    if not db_manager.is_user_admin(user_id):
        await update.message.reply_text("❌ Unauthorized!")
        return
    
    message = update.message.text.replace('/broadcast ', '')
    
    if not message:
        await update.message.reply_text("❌ Please provide a message to broadcast.")
        return
    
    # Get all users
    users_ref = db_manager.db.child('users')
    all_users = users_ref.get()
    
    if not all_users:
        await update.message.reply_text("❌ No users found.")
        return
    
    success_count = 0
    for uid in all_users.keys():
        try:
            await context.bot.send_message(
                chat_id=int(uid),
                text=f"📢 *Broadcast Message*\n\n{message}",
                parse_mode=ParseMode.MARKDOWN
            )
            success_count += 1
        except:
            pass
    
    await update.message.reply_text(f"✅ Broadcast sent to {success_count}/{len(all_users)} users.")

# ============ MAIN FUNCTION ============

def main():
    """Start the bot"""
    # Create Application
    application = Application.builder().token(Config.BOT_TOKEN).build()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("balance", balance_command))
    application.add_handler(CommandHandler("withdraw", withdraw_command))
    application.add_handler(CommandHandler("advertise", advertise_command))
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CommandHandler("addtask", add_task_command))
    application.add_handler(CommandHandler("broadcast", broadcast_command))
    
    # Add callback query handler
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Add message handler
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Start bot
    print("🤖 Bot is starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
