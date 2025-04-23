from flask import Flask, request, render_template
import numpy as np
import pandas as pd
import joblib  
import urlclassifier
import requests
import logging
from initdb import URLdb

app = Flask(__name__)

model = joblib.load("k-nearest_neighbors_model.joblib")

numerical_cols = ['url_has_login', 'url_has_client', 'url_has_server', 'url_has_admin', 'url_has_ip', 'url_isshorted', 'url_len', 'url_count_dot', 'url_count_https', 'url_count_http', 'url_count_perc', 'url_count_hyphen', 'url_count_www', 'url_count_atrate', 'url_count_hash', 'url_count_semicolon', 'url_count_underscore', 'url_count_ques', 'url_count_equal', 'url_count_amp', 'url_count_letter', 'url_count_digit', 'path_len', 'path_count_no_of_dir', 'path_count_zero', 'path_count_pertwent', 'path_count_lower', 'path_count_upper', 'path_has_singlechardir', 'path_has_upperdir', 'query_len', 'query_count_components', 'pdomain_len', 'pdomain_count_hyphen', 'pdomain_count_atrate', 'pdomain_count_non_alphanum', 'pdomain_count_digit', 'tld_len']
full_cols = [
    'url_login_keyword', 'url_financial_keyword', 'url_technical_keyword',
    'url_social_keyword', 'url_has_ip', 'url_isshorted', 'url_len',
    'url_count_dot', 'url_count_perc', 'url_count_hyphen', 'url_count_atrate',
    'url_count_hash', 'url_count_semicolon', 'url_count_underscore',
    'url_count_ques', 'url_count_equal', 'url_count_amp', 'url_count_letter',
    'url_count_digit', 'path_len', 'path_count_no_of_dir', 'path_count_zero',
    'path_count_pertwent', 'path_count_lower', 'path_count_upper',
    'path_has_singlechardir', 'path_has_upperdir', 'query_len',
    'query_count_components', 'pdomain_len', 'pdomain_count_hyphen',
    'pdomain_count_atrate', 'pdomain_count_non_alphanum',
    'pdomain_count_digit', 'tld_len', 'tld', 'domain_age',
    'subdomain_depth', 'url_entropy', 'suspicious_extensions', 'has_port'
]

logging.basicConfig(
    level=logging.DEBUG, 
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  
        logging.StreamHandler() 
    ]
)

@app.route("/", methods=["GET", "POST"])
def home():
    image_url = None
    prediction = None
    url = ''
    
    logging.info("Home route accessed")

    if request.method == "POST":
        database = URLdb('URL.db')
        message = request.form.get("message") 
        logging.info(f"Message received: {message}")  
        
        check = database.check_ip_db(message)

        if check == -1:
            prediction = predict(message)
        
        if check == 0:
            prediction = '100'
        
        if check == 1:
            prediction = '0'

        image_url = get_image(message) 
        url = message
        save = database.record_results(message,prediction)
        logging.info(save)
        logging.info(message,prediction)

        database.close()

    return render_template("test.html", image_url=image_url, prediction=prediction, url=url)

@app.route("/feedback", methods=["POST"])
def feedback():
    feedback = request.form.get("feedback") 
    url = request.form.get("url") 
    prediction = request.form.get("prediction") 

    if feedback and url and prediction:
        url_list = [url] 
        logging.info(f"Feedback received: {feedback}")
        logging.info(f"URL associated: {url_list} {prediction}")

        database = URLdb('URL.db')
        database.record_feedback(url,prediction,feedback)
        logging.info("Feedback Saved")


    return "Feedback submitted successfully!", 200 

def predict(URL):
    tags = urlclassifier.build_url(URL) 
    tags_df = pd.DataFrame([tags], columns=full_cols)

    prediction = (model.predict(tags_df))
    percent = model.predict_proba(tags_df)[0][prediction]
    logging.info((percent))
    if prediction == 0:
        percent = 1-percent[0]
    else:
        percent = percent[0]
    return f"{percent:.2%}"

def get_image(URL):
    api = "https://screenshotty1.p.rapidapi.com/api/v1/screenshot"
    payload = {
	"url": URL,
	"viewportWidth": 1920,
	"viewportHeight": 1080,
	"format": "image/png",
	"responseType": "url",
	"waitTime": 5000,
	"omitBackground": True,
	"screenshotWidth": 1920,
	"screenshotHeight": 1080
}
    headers = {
        "x-rapidapi-key": "40ca973889msh97518e3233ef4c0p15d6ddjsn4e074fffd248",
        "x-rapidapi-host": "screenshotty1.p.rapidapi.com",
        "Content-Type": "application/json"
    }

    response = requests.post(api, json=payload, headers=headers)
    if response.status_code == 200:
        return response.json().get('url')
    else:
        logging.info(f"Failed to get image for {URL}: {response.status_code}")
        return None

if __name__ == "__main__":
    try:
        app.run(debug=True, port = 5050)
    except:
        input()
