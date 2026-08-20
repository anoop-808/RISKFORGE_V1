from flask import Flask, render_template, request

from engine_vantage.database import save_scan_results
from engine_vantage.formatter import make_readable
from engine_vantage.vantage import run_vantage


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target_ip")

    result = run_vantage(target)

    save_scan_results(result)

    readable = make_readable(result)

    return render_template(
        "results.html",
        results=readable,
        target=target
    )


if __name__ == "__main__":
    app.run(debug=True)
