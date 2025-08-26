from flask import Flask
from database import db

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key_here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db.init_app(app)


@app.route("/", methods=["GET"])
def home():
    return "Welcome to the Flask App!"


if __name__ == "__main__":
    app.run(debug=True)
