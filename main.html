import telebot
from telebot import types
from pymongo import MongoClient

# --- CONFIGURATION ---
API_TOKEN = '8384600981:AAFOkWJEw0zPqouHrwFUYw9LI7m-eLBp1KE'
MONGO_URI = 'YOUR_MONGODB_CONNECTION_STRING_HERE'
ADMIN_PASSWORD = 'Vansh@000'
ADMIN_ID = @Vanshranaop90  # Apna Telegram ID yahan dalein

bot = telebot.TeleBot(API_TOKEN)
client = MongoClient(MONGO_URI)
db = client['crypto_earning_db']
users_col = db['users']

# --- DATABASE FUNCTIONS ---
def get_user(user_id, username):
    user = users_col.find_one({"user_id": user_id})
    if not user:
        user = {
            "user_id": user_id,
            "username": username,
            "balance": 0.0,
            "tasks_completed": 0,
            "is_admin": False
        }
        users_col.insert_one(user)
    return user

# --- KEYBOARDS ---
def main_keyboard():
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add('📝 Task', '🔗 Visit Link', '💰 Balance')
    markup.add('💸 Withdrawal', '📢 Advertisement')
    return markup

def admin_keyboard():
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add('📊 Total Users', '➕ Add Balance', '🔙 Back to Menu')
    return markup

# --- COMMANDS ---
@bot.message_handler(commands=['start'])
def start(message):
    get_user(message.chat.id, message.from_user.username)
    bot.send_message(message.chat.id, "👋 Welcome to Crypto Earning Bot!", reply_markup=main_keyboard())

# --- ADMIN PANEL ACTIVATION ---
@bot.message_handler(func=lambda message: message.text == ADMIN_PASSWORD)
def activate_admin(message):
    users_col.update_one({"user_id": message.chat.id}, {"$set": {"is_admin": True}})
    bot.send_message(message.chat.id, "✅ Admin Panel Activated!", reply_markup=admin_keyboard())

# --- MAIN LOGIC ---
@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    user_id = message.chat.id
    user_data = get_user(user_id, message.from_user.username)

    if message.text == '💰 Balance':
        bot.send_message(user_id, f"👤 User: @{user_data['username']}\n💰 Your Balance: {user_data['balance']} USDT")

    elif message.text == '📝 Task':
        bot.send_message(user_id, "Complete simple tasks to earn:\n1. Join our Channel\n2. Share Bot\n(Verify karne ke liye screenshot Admin ko bhejein)")

    elif message.text == '🔗 Visit Link':
        # Yahan aap apna Shortener link daal sakte hain
        bot.send_message(user_id, "🔗 Link par click karein aur 10 sec wait karein:\nhttps://yourlink.com\n\nReward: 0.01 USDT")

    elif message.text == '💸 Withdrawal':
        if user_data['balance'] >= 5.0:
            bot.send_message(user_id, "Enter your Wallet Address (TON/USDT):")
        else:
            bot.send_message(user_id, "❌ Minimum withdrawal is 5.0 USDT")

    elif message.text == '📢 Advertisement':
        bot.send_message(user_id, "Apna promotion karwane ke liye Admin @Vansh se contact karein.")

    # Admin Panel Actions
    elif message.text == '📊 Total Users' and user_data['is_admin']:
        count = users_col.count_documents({})
        bot.send_message(user_id, f"Total Users in Bot: {count}")

    elif message.text == '🔙 Back to Menu':
        bot.send_message(user_id, "Main Menu", reply_markup=main_keyboard())

print("Bot is running...")
bot.polling()
