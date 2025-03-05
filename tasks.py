from celery import Celery
import logging
import telebot

import os
from dotenv import load_dotenv

load_dotenv()

BROKER_URL = os.getenv("BROKER_URL")


# Replace with your bot token
TOKEN = '7940187803:AAHzZdoxGo2p2OLwHS7uWWrh7sc_dsI73sc'
bot = telebot.TeleBot(TOKEN)

# Initialize Celery
celery = Celery('tasks', broker=BROKER_URL)



# Define the task to send a Telegram message
@celery.task
def send_message(chat_id, message):
    try:
        logging.info(f"Sending message to {chat_id}: {message}")
        bot.send_message(chat_id, message)
        logging.info(f"Message sent to {chat_id}")
    except Exception as e:
        logging.error(f"Failed to send message: {e}")
