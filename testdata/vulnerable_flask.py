from flask import Flask, request, jsonify

app = Flask(__name__)

# IDOR: no ownership check
@app.route("/api/users/<int:id>", methods=["GET"])
def get_user(id):
    user = User.query.get(id)
    return jsonify(user.to_dict())

# Missing auth on admin route
@app.route("/api/admin/settings", methods=["POST"])
def update_settings():
    data = request.get_json()
    Settings.update(data)
    return jsonify({"status": "ok"})

# Mass assignment
@app.post("/api/users/<int:id>/profile")
def update_profile(id):
    data = request.get_json()
    user = User.query.get(id)
    for key, value in data.items():
        setattr(user, key, value)
    db.session.commit()
    return jsonify(user.to_dict())
