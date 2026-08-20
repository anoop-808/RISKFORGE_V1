from flask import Flask, render_template, request

from engine_vantage.scanner import scan_target
from engine_vantage.database import save_scan_results
from engine_vantage.formatter import make_readable


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target_ip")

    raw_results = scan_target(target)

    save_scan_results(raw_results)

    readable = make_readable(raw_results)

    return render_template(
        "results.html",
        results=readable,
        target=target
    )


if __name__ == "__main__":
    app.run(debug=True)
