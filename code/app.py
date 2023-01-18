#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
import feature_extraction 


# file.close()


app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    if request.method == "POST":

        url = request.form["url"] 
        x = np.array(feature_extraction.getFeatures(url)).reshape(1,10) 
        gbc = pickle.load(open("model.pkl","rb"))
        y_pred =gbc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_non_phishing = gbc.predict_proba(x)[0,0]
        y_pro_phishing = gbc.predict_proba(x)[0,1]
        print(y_pro_non_phishing," ",y_pro_phishing, "pred: ",y_pred)
        if(y_pred ==1 ):
            pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        else:
            pred = "It is {0:.2f} % unsafe to go ".format(y_pro_non_phishing*100)
        # return render_template('index.html',xx =round(y_pro_phishing,2),url=url )
        return render_template('predict.html',prediction_text=pred)
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)