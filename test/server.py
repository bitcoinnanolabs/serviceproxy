import zmq

def server():
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.connect("tcp://localhost:5557")  # Altere para o endereço do seu backend

    while True:
        message = socket.recv()
        print("Recebeu requisição:", message)
        
        if message == b"Hello":
            print("Enviando resposta")
            socket.send(b"World")
        else:
            socket.send(b"good")
            

if __name__ == "__main__":
    server()
