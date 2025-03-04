from celery import Celery
import logging
import telebot

# Replace with your bot token
TOKEN = '7940187803:AAHzZdoxGo2p2OLwHS7uWWrh7sc_dsI73sc'
bot = telebot.TeleBot(TOKEN)

# Initialize Celery
celery = Celery('tasks', broker='pyamqp://guest@localhost//')



# Define the task to send a Telegram message
@celery.task
def send_message(chat_id, message):
    try:
        logging.info(f"Sending message to {chat_id}: {message}")
        bot.send_message(chat_id, message)
        logging.info(f"Message sent to {chat_id}")
    except Exception as e:
        logging.error(f"Failed to send message: {e}")
