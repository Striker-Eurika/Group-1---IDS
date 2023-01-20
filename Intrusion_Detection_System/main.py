import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style
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
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Database connection details
host = "localhost"
dbname = "intrusion_db"
user = "ids_user"
pwd = "ids_pass_123"

# Create connection to MySQL database
db = MySQLdb.connect(host,user,pwd,dbname) or die("Not connected!")

# Dictionary to hold attack label and attack_id (for MySQL database)
attacks = {'DDoS' : 1, 'PortScan': 2, 'Bot': 3, 'Infiltration': 4, 'Brute Force': 5, 'XSS': 6, 'Sql Injection': 7, 'FTP-Patator': 8, 'SSH-Patator': 9, 'DoS slowloris': 10, 'DoS Slowhttptest': 11, 'DoS Hulk': 12, 'DoS GoldenEye': 13, 'Heartbleed': 14}


flow_count = 0
anomaly_count = 0


# This class is used to monitor the folder for any new CSV files
class MonitorFolder(FileSystemEventHandler):
	def on_created(self, event):
		filename = event.src_path # Get new filename
		if filename.endswith('.csv'): # If the file is a .csv file
			print('New flow data created @', event.src_path) # Display filename
			time.sleep(4) # Wait 4 seconds for CICFlowMeter to finish conversion
			load_flows(event.src_path) # Load flows from the new file


# Function used to load flows from .csv
def load_flows(src_path):
	df_flow = pd.DataFrame() # Define new DataFrame
	#csv_files = []
	#dir_path = 'TCPDUMP_and_CICFlowMeter-master/csv/' + datetime.now().strftime("%d_%m_%Y")
	#dir_path = 'TCPDUMP_and_CICFlowMeter-master/csv/15_12_2022'
	#for file in os.listdir(src_path):
		#if file.endswith('.csv'):
	df_flow = pd.read_csv(src_path) # Read flows from .csv
	#df_flow = pd.concat(csv_files)
	print('Loaded', df_flow.shape[0] - 1, 'flows!') # Display amount of flows loaded. -1 because one row is always extra
	global df_detail # Define global DataFrame for details
	df_flow = preprocess_dataset(df_flow) # Preprocess the new input data
	df_detail = df_flow
	prepare_input(df_flow) # Prepare the input for prediciton
	#return df_flow


# Load prediction labels from .txt file
def load_labels():
	class_list = []
	with open(r'labels.txt', 'r') as label_file:
		for line in label_file:
			next_label = line[:-1]
			class_list.append(next_label)
	print('Labels loaded.')
	return class_list


# Function used to preprocess dataset
def preprocess_dataset(df_flow):
	df_flow = df_flow[df_flow["Flow ID"].str.contains("Flow ID") == False] # Remove the glitched extra columns row that gets added to the .csv
	df_flow = fix_data_types(df_flow) # Fix the data types
	df_flow = df_flow.drop(columns=['Flow ID','Src IP','Src Port','Timestamp','Protocol','Dst IP']) # Drop unnecesssary columns
	pd.set_option('use_inf_as_na',True)
	df_flow = df_flow.replace('Infinity',np.nan) # Replace all infinity with NaN
	print('Dropping', df_flow.isna().sum().sum(), 'NaN/Null/Infinity value rows...')
	df_flow = df_flow.dropna(axis = 0, how = 'any')
	# df_flow.dropna(inplace=True)
	return df_flow


# Function used to fix data types
def fix_data_types(df_flow):
	with open('datatypes_dictionary.pickle', 'rb') as handle:
		cols = pickle.load(handle)
	df_flow = df_flow.astype(cols)
	return df_flow


# Encode labels for prediction model
def encode_labels():
	class_list = load_labels()
	label_encoder = preprocessing.LabelEncoder() # each feature vector is given a number based on string
	label_encoder.fit_transform(class_list) # the number is applied
	return label_encoder


def prepare_input(df_flow):
	sc = MinMaxScaler() # calculate standard number between 0-1 for each cell

	x = pd.get_dummies(df_flow.drop(columns = (['Label']))) # dataset without the label column
	x = sc.fit_transform(x) # cells tranformed and fitted simultaneously with scaler

	df_flow = df_flow.drop(columns=(['Label']))
	predict_from_flow(sc.transform(df_flow), model, label_encoder)
	#return sc.transform(df_flow)
	#scaler_transform = joblib.load('scaler_transform.joblib')
	#return scaler_transform


def predict_from_flow(fitted_input, model, label_encoder):
	pred = model.predict(fitted_input) # a confidence number for each attack type is given

	pred_class = np.argmax(pred, axis=-1) # the highest confidence rating is selected

	predict = label_encoder.inverse_transform(pred_class)
	list_predictions = predict.tolist()
	list_anomalies = []
	list_rows_of_interest = []
	for i in range (len(list_predictions)):
		if list_predictions[i] != 'BENIGN':
			print('Anomaly predicted to be', list_predictions[i], 'detected. Confidence: ', pred[i].max())
			list_anomalies.append(list_predictions[i])
			log_intrusion(list_predictions[i])
			log_details(df_detail.iloc[i])
	global flow_count
	global anomaly_count
	flow_count = len(list_predictions)
	anomaly_count = len(list_anomalies)
	#visualization()
	print('Scanned', flow_count, 'flow(s) and detected', anomaly_count, 'anomalies.')
	print('\nMonitoring...')


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


def log_details(row):
	try:
		cursor = db.cursor()
		try:
			cursor.execute("SELECT * FROM intrusion ORDER BY intrusion_id DESC LIMIT 1")
			result = cursor.fetchall()
			intrusion_id = result[0][0]
			cursor.execute("INSERT INTO detail VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (intrusion_id,row['Dst Port'],row['Flow Duration'],row['Total Fwd Packet'],row['Total Bwd packets'],row['Total Length of Fwd Packet'],row['Total Length of Bwd Packet'],row['Fwd Packet Length Max'],row['Fwd Packet Length Min'],row['Fwd Packet Length Mean'],row['Fwd Packet Length Std'],row['Bwd Packet Length Max'],row['Bwd Packet Length Min'],row['Bwd Packet Length Mean'],row['Bwd Packet Length Std'],row['Flow Bytes/s'],row['Flow Packets/s'],row['Flow IAT Mean'],row['Flow IAT Std'],row['Flow IAT Max'],row['Flow IAT Min'],row['Fwd IAT Total'],row['Fwd IAT Mean'],row['Fwd IAT Std'],row['Fwd IAT Max'],row['Fwd IAT Min'],row['Bwd IAT Total'],row['Bwd IAT Mean'],row['Bwd IAT Std'],row['Bwd IAT Max'],row['Bwd IAT Min'],row['Fwd PSH Flags'],row['Bwd PSH Flags'],row['Fwd URG Flags'],row['Bwd URG Flags'],row['Fwd Header Length'],row['Bwd Header Length'],row['Fwd Packets/s'],row['Bwd Packets/s'],row['Packet Length Min'],row['Packet Length Max'],row['Packet Length Mean'],row['Packet Length Std'],row['Packet Length Variance'],row['FIN Flag Count'],row['SYN Flag Count'],row['RST Flag Count'],row['PSH Flag Count'],row['ACK Flag Count'],row['URG Flag Count'],row['CWR Flag Count'],row['ECE Flag Count'],row['Down/Up Ratio'],row['Average Packet Size'],row['Fwd Segment Size Avg'],row['Bwd Segment Size Avg'],row['Fwd Bytes/Bulk Avg'],row['Fwd Packet/Bulk Avg'],row['Fwd Bulk Rate Avg'],row['Bwd Bytes/Bulk Avg'],row['Bwd Packet/Bulk Avg'],row['Bwd Bulk Rate Avg'],row['Subflow Fwd Packets'],row['Subflow Fwd Bytes'],row['Subflow Bwd Packets'],row['Subflow Bwd Bytes'],row['FWD Init Win Bytes'],row['Bwd Init Win Bytes'],row['Fwd Act Data Pkts'],row['Fwd Seg Size Min'],row['Active Mean'],row['Active Std'],row['Active Max'],row['Active Min'],row['Idle Mean'],row['Idle Std'],row['Idle Max'],row['Idle Min'],))
			db.commit()
			
			cursor.close()
		except MySQLdb.IntegrityError:
			print("Database insert has failed!")
		finally:
			cursor.close()
	except Exception as e:
		print(e)
	

def visualization():
	style.use('fivethirtyeight')
	figure, axis = plt.subplots(1, 2)
	 
	X = list_time_scans
	Y1 = list_flow_counts
	Y2 = list_anomaly_counts

	axis[0].plot(X, Y1)
	axis[0].set_title("Flows over time")
	axis[1].plot(X, Y2)
	axis[1].set_title("Anomalies over time")
	plt.show()


# This function is called periodically from FuncAnimation
def animate(i, xs, ys):
	xs.append(datetime.now().strftime('%H:%M:%S'))
	ys.append(flow_count)
	xs = xs[-20:]
	ys = ys[-20:]
	ax.clear()
	ax.plot(xs, ys)
	plt.xticks(rotation=45, ha='right')
	plt.subplots_adjust(bottom=0.30)
	plt.title('Flows scanned over time')
	plt.ylabel('Flows scanned')


def visual():
	os.system('cls' if os.name == 'nt' else 'clear')
	print("----")
	print("Group 1 - Cybersecurity and Data Analytics")
	print("INTRUSION DETECTION SYSTEM")
	print("Patryk Kaiser, Daniel Mackey, Ingrid Melin")
	print("----")
	print("\nMonitoring...")
	

if __name__ == "__main__":
	dir_path = 'TCPDUMP_and_CICFlowMeter-master/csv/' + datetime.now().strftime("%d_%m_%Y")
	model = keras.models.load_model("modelfixed.h5")
	label_encoder = encode_labels()
	event_handler=MonitorFolder()
	observer = Observer()
	observer.schedule(event_handler, path=dir_path, recursive=True)
	observer.start()
	visual()
	fig = plt.figure()
	ax = fig.add_subplot(1, 1, 1)
	xs = []
	ys = []
	ani = animation.FuncAnimation(fig, animate, fargs=(xs, ys), interval=30000)
	plt.show()
	try:
		while(True):
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
		observer.join()
