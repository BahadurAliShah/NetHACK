from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO

async_mode = None

app = Flask(__name__)
socket_ = SocketIO(app, async_mode=async_mode, cors_allowed_origins="*")
CORS(app)


