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
import joblib


# Database connection details
host = "localhost"
dbname = "intrusion_db"
user = "ids_user"
pwd = "ids_pass_123"

# Create connection to MySQL database
db = MySQLdb.connect(host,user,pwd,dbname) or die("Not connected!")

# Dictionary to hold attack label and attack_id (for MySQL database)
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
	print('Loaded', df.shape[0], 'flows!')
	df = preprocess_dataset(df)
	return df


def load_labels():
	class_list = []
	with open(r'labels.txt', 'r') as label_file:
		for line in label_file:
			next_label = line[:-1]
			class_list.append(next_label)
	print('Labels have successfully been loaded!')
	return class_list


def preprocess_dataset(df):
	df = df[df["Flow ID"].str.contains("Flow ID") == False] # Remove the glitched extra columns row that gets added to the CSV
	df = fix_data_types(df)
	df = df.drop(columns=['Flow ID','Src IP','Src Port','Timestamp','Protocol','Dst IP']) # Drop unnecesssary columns
	pd.set_option('use_inf_as_na',True)
	df = df.replace('Infinity',np.nan)
	print('Dropping', df.isna().sum().sum(), 'NaN/Null/Infinity value rows...')
	df = df.dropna(axis = 0, how = 'any')
	# df.dropna(inplace=True)
	
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
	#scaler_transform = joblib.load('scaler_transform.joblib')
	#return scaler_transform


def predict_from_flow(fitted_input, model, label_encoder):
	intrusions = []
	pred = model.predict(fitted_input)

	pred_class = np.argmax(pred, axis=-1)

	predict = label_encoder.inverse_transform(pred_class)
	predict_list = predict.tolist()

	for prediction in predict_list:
		if prediction != 'BENIGN':
			print('Attack of type:', prediction, 'detected!')
			intrusions.append(prediction)
			log_intrusion(prediction)
	print('Scanned', len(df), 'flows and detected', len(intrusions), 'intrusions.')


def log_intrusion(attack_type):
	attack_id = attacks[attack_type]
	try:
		cursor = db.cursor()
		try:
			cursor.execute("INSERT INTO intrusion VALUES (DEFAULT, %s, DEFAULT)", (attack_id,))
			db.commit()
			cursor.close()
		except MySQLdb.IntegrityError:
			print("Database insert has failed!")
		finally:
			cursor.close()
	except Exception as e:
		print(e)


if __name__ == "__main__":
	model = keras.models.load_model("Model200kBenignAdded.h5")
	df = load_flows()
	label_encoder = encode_labels()
	fitted_input = prepare_input(df)
	predict_from_flow(fitted_input, model, label_encoder)
