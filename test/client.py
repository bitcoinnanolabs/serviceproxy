import zmq

def client():
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://localhost:5556")  # Altere para o endereço do seu proxy

    print("Enviando requisição")
    socket.send(b"o")

    message = socket.recv()
    print("Recebeu resposta:", message)

if __name__ == "__main__":
    client()
