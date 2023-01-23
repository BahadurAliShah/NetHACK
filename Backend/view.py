from gevent import monkey
monkey.patch_all()

# import grpc._cython.cygrpc
# grpc._cython.cygrpc.init_grpc_gevent()

# from fmconsole.factory_app import create_app
# from fmconsole.factory_utils import socketio
from threading import Thread, Event
import time
from flask_socketio import emit
from Packages import Sniffer
from Packages import Interfaces
from flask_restful import Resource, Api
from app import app, socket_
# from gevent.pywsgi import WSGIServer
# from geventwebsocket.handler import WebSocketHandler

api = Api(app)
api.add_resource(Sniffer, '/sniffer')
api.add_resource(Interfaces, '/interfaces')

def sniffer(socket):
    for i in range(10):
        socket.emit('sniffing', {'data': i})
        print(i)
        time.sleep(1)


thread = Thread()
thread_stop_event = Event()
Continue = True
class DataThread(Thread):
    def __init__(self):
        self.delay = 0.5
        super(DataThread, self).__init__()
    def dataGenerator(self):
        global Continue
        print("Initialising")
        try:
            i=0
            while Continue:
            # while not thread_stop_event.isSet():
                # socket_.emit('responseMessage', {'temperature': round(random()*10, 3)})
                # time.sleep(self.delay)
                i+=1
                socket_.emit('sniffing', {'data': i})
                print(i, Continue)

                socket_.sleep(1)
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            # kill()
            print("Keyboard  Interrupt")
    def run(self):
        self.dataGenerator()




@socket_.on('start_sniffing')
def start_sniffing(data):
    global thread, Continue
    print('someone connected to websocket')
    Continue = True
    emit('sniffing', {'data': 'Connected! ayy'})
    # need visibility of the global thread object
    # if not thread.is_alive():
    print("Starting Thread", Continue)
    thread_stop_event.clear()
    thread = DataThread()
    thread.start()

@socket_.on('stop_sniffing')
def stop_sniffing():
    # print('someone sent to the websocket', message)
    # print('Data', message["data"])
    # print('Status', message["status"])
    global thread, Continue
    global thread_stop_event
    # thread_stop_event.set()
    Continue = False
    print("Continue", Continue)
    # if (message["status"]=="Off"):
    print("Stopping Threadddddddd")
    # print("ssssssssssssssssss",thread.is_alive())
    # if thread.is_alive():
    #     thread_stop_event.set()
    #     print("Stopping Thread")
    # else:
    #     print("Thread not alive")
    # elif (message["status"]=="On"):
    #     if not thread.isAlive():
    #         thread_stop_event.clear()
    #         print("Starting Thread")
    #         thread = DataThread()
    #         thread.start()
    # else:
    #     print("Unknown command")


if __name__ == '__main__':
    socket_.run(app, debug=True, host='127.0.0.1', port=5000)
    # app.run(debug=True, host='127.0.0.1', port=5000)

    # http_server = WSGIServer(('127.0.0.1',5000), app, handler_class=WebSocketHandler)
    # http_server.serve_forever()
