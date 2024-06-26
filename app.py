from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import random
from string import ascii_uppercase
from aes_encrypton import *

app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdahhds"
socketio = SocketIO(app)

rooms = {}

def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    
    return code

@app.route("/", methods=["GET"])
def home():
    session.clear()
    # if request.method == "POST":
    #     name = request.form.get("name")
    #     code = request.form.get("code")
    #     join = request.form.get("join", False)
    #     create = request.form.get("create", False)
    #
    #     if not name:
    #         return render_template("welcome.html", error="Please enter a name.", code=code, name=name)
    #
    #     if join != False and not code:
    #         return render_template("joinRoom.html", error="Please enter a room code.", code=code, name=name)
    #
    #     room = code
    #     if create != False:
    #         room = generate_unique_code(4)
    #         rooms[room] = {"members": 0, "messages": []}
    #     elif code not in rooms:
    #         return render_template("/joinRoom.html", error="Room does not exist.", code=code, name=name)
    #
    #     session["room"] = room
    #     session["name"] = name
    #     return redirect(url_for("room"))

    return render_template("welcome.html")

@app.route("/createRoom", methods=["GET", "POST"])
def createroom():
    if request.method == "POST":
        name = request.form.get("name")

        if not name:
            return render_template("createRoom.html", error="Please enter a name.", name=name)

        create = request.form.get("create")
        if create != False:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": []}

        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("createRoom.html")

@app.route("/joinRoom", methods=["GET", "POST"])
def joinroom():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")

        if not name:
            return render_template("joinRoom.html", error="Please enter a name.", code=code, name=name)

        if not code:
            return render_template("joinRoom.html", error="Please enter a room code.", code=code, name=name)

        room = code
        if code not in rooms:
            return render_template("joinRoom.html", error="Room does not exist.", code=code, name=name)

        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))
    return render_template("joinRoom.html")

@app.route("/room", methods=["GET", "POST"])
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("welcome"))

    return render_template("room.html", code=room, messages=rooms[room]["messages"])

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    key = session.get("room")
    message = data['data']

    encrypted_message = encrypt_message(key, message)
    decrypted_message = decrypt_message(key, encrypted_message)

    content = {
        "name": session.get("name"),
        "message": decrypted_message
    }
    send(content, to=room)
    print(encrypted_message)
    rooms[room]["messages"].append(encrypted_message)
    print(f"{session.get('name')} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    send({"name": name, "message": "has left the room"}, to=room)
    print(f"{name} has left the room {room}")

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', debug=True, allow_unsafe_werkzeug=True)
