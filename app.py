from flask import Flask, render_template, request
from FeatureExtraction import extract_features
import pickle
import numpy as np

app = Flask(__name__)

# Load model once
XGBmodel = pickle.load(open('Phishing XGB classifier.pkl', 'rb'))

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        try:
            features = extract_features(url)
            features_array = np.array(features).reshape(1, -1)
            prediction = XGBmodel.predict(features_array)[0]
            result = "Legitimate Website" if prediction == 0 else "Phishing Website"
            return render_template('index.html', prediction_text=result)
        except Exception as e:
            return render_template('index.html', prediction_text=f"Error: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)