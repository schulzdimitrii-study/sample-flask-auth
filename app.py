from flask import Flask
from src.models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from database import db
from flask import request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key_here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# view login
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso!"})

    return jsonify({"message": "Credenciais Inválidas"}), 401

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

@app.route("/users", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Usuário criado com sucesso!"}), 201

    return jsonify({"message": "Dados inválidos"}), 400

@app.route("/", methods=["GET"])
def home():
    return "Welcome to the Flask App!"


if __name__ == "__main__":
    app.run(debug=True)
