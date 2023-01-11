from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_restful import Resource, Api

from Packages import Sniffer
from Packages import Interfaces

app = Flask(__name__)
CORS(app)

api = Api(app)
api.add_resource(Sniffer, '/sniffer')
api.add_resource(Interfaces, '/interfaces')

if __name__ == '__main__':
    app.run(debug=True)

