from flask_socketio import emit
from Packages import Interfaces
from flask_restful import Api
from app import app, socket_

api = Api(app)
api.add_resource(Interfaces, '/interfaces')


if __name__ == '__main__':
    socket_.run(app, debug=True, host='127.0.0.1', port=5000)

