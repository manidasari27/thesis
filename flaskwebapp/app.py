import json
import pickle
import sklearn
import requests
import numpy as np
import pandas as pd
from pefeatureext import *
from flask import Flask, request, render_template

app = Flask(__name__)
try:
  with open('models/best_model.pkl', 'rb') as r:
          model= pickle.load(r)
          print('Model Loaded sucessfully!')
except Exception as e:
  print(e)
col = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection','https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic','Domain_Age', 'Domain_End', 'GoogleIndex']



@app.route('/')
def home(): 
  return render_template('index.html')

@app.route('/index')
def index(): 
  return render_template('index.html')

@app.route('/service')
def service():
  return render_template('detection.html')

@app.route('/urldetectorsys', methods=['POST'])
def urldetectorsys():
  url = request.form["url"]
  datalist = urlfeature_extractor(url)
  dataframe = pd.DataFrame([datalist], columns= col)
  dataframe.drop(['Domain'], axis='columns', inplace=True)
  dataframe = np.array(dataframe)
  y_pred=model.predict(dataframe)

  if y_pred == 1:
    outputres = "ALERT URL DETECTED AS PHISHING !"
    return render_template('detection.html', output = outputres, inpurl = url)

  else:
    outputres = "URL DETECTED AS SAFE !"
    return render_template('detection.html', output = outputres, inpurl = url)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

