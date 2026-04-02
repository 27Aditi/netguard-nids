from flask import Flask, render_template
import os

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)), debug=False)