import telebot
from telebot import types

# --- CONFIGURATION ---
API_TOKEN = '8384600981:AAFOkWJEw0zPqouHrwFUYw9LI7m-eLBp1KE' # @BotFather se lein
ADMIN_PASSWORD = 'Vansh@000'

bot = telebot.TeleBot(API_TOKEN)

# --- KEYBOARDS ---
def main_keyboard():
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    # Aapke kahe anusar buttons
    btn1 = types.KeyboardButton('📝 Task')
    btn2 = types.KeyboardButton('🔗 Visit Link')
    btn3 = types.KeyboardButton('💰 Balance')
    btn4 = types.KeyboardButton('💸 Withdrawal')
    btn5 = types.KeyboardButton('📢 Advertisement')
    markup.add(btn1, btn2, btn3, btn4, btn5)
    return markup

def admin_keyboard():
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add('📊 Total Users', '🔙 Back to Menu')
    return markup

# --- BOT LOGIC ---

# 1. Start Command
@bot.message_handler(commands=['start'])
def start(message):
    bot.send_message(
        message.chat.id, 
        "👋 Hello! Welcome to the Earning Bot Structure.\nNiche diye gaye buttons check karein:", 
        reply_markup=main_keyboard()
    )

# 2. Admin Panel Activation (Password check)
@bot.message_handler(func=lambda message: message.text == ADMIN_PASSWORD)
def activate_admin(message):
    bot.send_message(
        message.chat.id, 
        "✅ Admin Panel Active! Aapka swagat hai Vansh.", 
        reply_markup=admin_keyboard()
    )

# 3. Message Handling for Buttons
@bot.message_handler(func=lambda message: True)
def handle_buttons(message):
    if message.text == '💰 Balance':
        bot.send_message(message.chat.id, "💰 Your Balance: 0.00 USDT (Demo)")

    elif message.text == '📝 Task':
        bot.send_message(message.chat.id, "📝 Tasks List:\n1. YouTube Subscribe\n2. Telegram Join\n(Coming Soon...)")

    elif message.text == '🔗 Visit Link':
        bot.send_message(message.chat.id, "🔗 Shortener Link:\nhttps://example.com/earn")

    elif message.text == '💸 Withdrawal':
        bot.send_message(message.chat.id, "💸 Minimum Withdrawal: 5 USDT")

    elif message.text == '📢 Advertisement':
        bot.send_message(message.chat.id, "📢 Promo Service: Contact @Admin for ads.")

    elif message.text == '📊 Total Users':
        bot.send_message(message.chat.id, "📊 Demo Mode: 1 Active User (You)")

    elif message.text == '🔙 Back to Menu':
        bot.send_message(message.chat.id, "Returning to Main Menu...", reply_markup=main_keyboard())

# Bot Polling
print("Bot structure is running...")
bot.infinity_polling()
