import numpy as np
from tensorflow import keras
import tensorflow as tf
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn import metrics
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
from sklearn.metrics import accuracy_score
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from datetime import datetime
import os
import pickle
import MySQLdb
from enum import Enum


host = "localhost"
dbname = "intrusion_db"
user = "ids_user"
pwd = "ids_pass_123"

db = MySQLdb.connect(host,user,pwd,dbname) or die("Not connected!")

attacks = {'DDoS' : 1, 'PortScan': 2, 'Bot': 3, 'Infiltration': 4, 'Brute Force': 5, 'XSS': 6, 'Sql Injection': 7, 'FTP-Patator': 8, 'SSH-Patator': 9, 'DoS slowloris': 10, 'DoS Slowhttptest': 11, 'DoS Hulk': 12, 'DoS GoldenEye': 13, 'Heartbleed': 14}
	

def load_flows():
	df = pd.DataFrame()
	csv_files = []
	#dir_path = 'TCPDUMP_and_CICFlowMeter-master/csv/' + datetime.now().strftime("%d_%m_%Y")
	dir_path = 'TCPDUMP_and_CICFlowMeter-master/csv/15_12_2022'
	for file in os.listdir(dir_path):
		if file.endswith('.csv'):
		    csv_files.append(pd.read_csv(dir_path + '/' + file))
	df = pd.concat(csv_files)
	df = preprocess_dataset(df)
	return df

def load_labels():
	class_list = []
	with open(r'labels.txt', 'r') as label_file:
		for line in label_file:
			next_label = line[:-1]
			class_list.append(next_label)
	return class_list


def preprocess_dataset(df):
	df = df[df["Flow ID"].str.contains("Flow ID") == False]
	df = fix_data_types(df)
	df = df.drop(columns=['Flow ID','Src IP','Src Port','Timestamp','Protocol','Dst IP'])
	pd.set_option('use_inf_as_na',True)
	df.dropna(inplace=True)
	return df


def fix_data_types(df):
	with open('datatypes_dictionary.pickle', 'rb') as handle:
		cols = pickle.load(handle)
	df = df.astype(cols)
	return df


def encode_labels():
	class_list = load_labels()
	label_encoder = preprocessing.LabelEncoder()
	label_encoder.fit_transform(class_list)
	return label_encoder


def prepare_input(df):
	sc = MinMaxScaler()

	x = pd.get_dummies(df.drop(columns = (['Label'])))
	x = sc.fit_transform(x)

	df = df.drop(columns=(['Label']))

	return sc.transform(df)


def predict_from_flow(fitted_input, model, label_encoder):
	intrusions = []
	pred = model.predict(fitted_input)

	pred_class = np.argmax(pred, axis=-1)

	predict = label_encoder.inverse_transform(pred_class)
	predict_list = predict.tolist()

	for prediction in predict_list:
		if prediction != 'BENIGN':
			print(prediction)
			intrusions.append(prediction)
			log_intrusion(prediction)
	print(len(intrusions))
	print(len(predict_list))


def log_intrusion(attack_type):
	attack_id = attacks[attack_type]
	try:
		cursor = db.cursor()
		try:
			cursor.execute("INSERT INTO intrusion VALUES (DEFAULT, %s, DEFAULT)", (attack_id))
			db.commit()
			cursor.close()
		except MySQLdb.IntegrityError:
			print("Insert failed!")
		finally:
			cursor.close()
	except Exception as e:
		print(e)


model = keras.models.load_model("CIC_IDS_2017_COMPILED_FixedColumns-Model.h5")
df = load_flows()
label_encoder = encode_labels()
fitted_input = prepare_input(df)
predict_from_flow(fitted_input, model, label_encoder)
