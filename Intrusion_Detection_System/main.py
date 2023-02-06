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


# The below variables are used to keep track of flow counts. These counts reset once a .csv file of flows has been processed.
flow_count = 0 # This is to initialize the flow count to 0
anomaly_count = 0 # This is to initialize the anomaly count to 0


graph_update_interval_ms = 30000 # Interval for animation of graph (how often the graph updates)


# This class is used to monitor the folder for any new CSV files
class MonitorFolder(FileSystemEventHandler):
	def on_created(self, event): # File has been created
		filename = event.src_path # Get new filename
		if filename.endswith('.csv'): # If the file is a .csv file
			print('New flow data created @', event.src_path) # Display filename
			time.sleep(4) # Wait 4 seconds for CICFlowMeter to finish conversion
			load_flows(event.src_path) # Load flows from the new file


# Function used to load flows from .csv
def load_flows(src_path): # Used to handle new flows
	df_flow = pd.DataFrame() # Define new DataFrame to hold our flows
	df_flow = pd.read_csv(src_path) # Read flows from .csv
	print('Loaded', df_flow.shape[0] - 1, 'flows!') # Display amount of flows loaded. -1 because one row is always extra
	df_flow = preprocess_dataset(df_flow) # Preprocess the new input data
	prepare_input(df_flow) # Prepare the input for prediciton
	#return df_flow

# Load prediction labels from .txt file
def load_labels():
	list_label = [] # Initialize list of labels
	with open(r'labels.txt', 'r') as label_file: # Open the labels.txt file
		for line in label_file: # For each line in the file
			list_label.append(line[:-1]) # Add the label to the list
	print('Labels loaded.')
	return list_label # Return the list of labels


# Function used to preprocess dataset
def preprocess_dataset(df_flow):
	df_flow = df_flow[df_flow["Flow ID"].str.contains("Flow ID") == False] # Remove the glitched extra columns row that gets added to the .csv
	df_flow = fix_data_types(df_flow) # Fix the data types
	global df_detail # Define global DataFrame for details
	df_detail = df_flow # Save copy of flow details into this DataFrame. This will allow us to keep the info corresponding to each predicted anomaly after the flow DataFrame is cleaned and transformed
	df_flow = df_flow.drop(columns=['Flow ID','Src IP','Src Port','Timestamp','Protocol','Dst IP']) # Drop unnecesssary columns
	pd.set_option('use_inf_as_na',True)
	df_flow = df_flow.replace('Infinity',np.nan) # Replace all infinity with NaN
	print('Dropping', df_flow.isna().sum().sum(), 'NaN/Null/Infinity value rows...')
	df_flow = df_flow.dropna(axis = 0, how = 'any')
	# df_flow.dropna(inplace=True)
	return df_flow


# Function used to fix data types
def fix_data_types(df_flow):
	with open('datatypes_dictionary.pickle', 'rb') as handle: # Opening the pickle file to read the column : datatype dictionary
		cols = pickle.load(handle)
	df_flow = df_flow.astype(cols) # Set the data types by passing in the dictionary
	return df_flow


# Encode labels for prediction model
def encode_labels():
	class_list = load_labels()
	label_encoder = preprocessing.LabelEncoder()
	label_encoder.fit_transform(class_list)
	return label_encoder


def prepare_input(df_flow):
	#sc = MinMaxScaler() # We are using the MinMax scaler from ScikitLearn, used to scale features to a given range
	sc = joblib.load('scaler_transformCIC17CIC18.joblib')
	x = pd.get_dummies(df_flow.drop(columns = (['Label'])))
	sc.transform(x) # Fitting the data

	df_flow = df_flow.drop(columns=(['Label'])) # Dropping label flow as we do not need it to perform a prediction. Prediction output will be the label
	predict_from_flow(sc.transform(df_flow), model, label_encoder) # Calling predict_from_flow function and passing the MinMax transformed flow data, the model and the label encoder
	#return sc.transform(df_flow)
	#
	#return scaler_transform


# Creates a list of predictions from fitted flow input, a model and a label encoder
def predict_from_flow(fitted_input, model, label_encoder):
	pred = model.predict(fitted_input)

	pred_class = np.argmax(pred, axis=-1)

	predict = label_encoder.inverse_transform(pred_class)
	list_predictions = predict.tolist()
	list_anomalies = []
	list_rows_of_interest = []
	for i in range (len(list_predictions)):
		if list_predictions[i] != 'BENIGN': # Ignore BENIGN label outputs
			print('Anomaly predicted to be', list_predictions[i], 'detected. Confidence: ', pred[i].max()) # Print a message if an anomaly has been identified
			list_anomalies.append(list_predictions[i]) # Add this prediction to the list of predictions
			log_intrusion(list_predictions[i]) # Call the function responsible for logging details of the intrusion into the MySQL database
			log_details(df_detail.iloc[i])# Another function responsible for MySQL. This method logs extra information about the anomalous flows into the database
	global flow_count
	global anomaly_count
	flow_count = len(list_predictions) # Set count of scanned flows
	anomaly_count = len(list_anomalies) # Set count of identified anomalies
	print('Scanned', flow_count, 'flow(s) and detected', anomaly_count, 'anomalies.') # Display details of scan
	print('\nAwaiting flow data...') # Inform program supervisor that the program is once again monitoring for new flow data


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
			cursor.execute("INSERT INTO detail VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (intrusion_id,row['Dst Port'],row['Flow Duration'],row['Total Fwd Packet'],row['Total Bwd packets'],row['Total Length of Fwd Packet'],row['Total Length of Bwd Packet'],row['Fwd Packet Length Max'],row['Fwd Packet Length Min'],row['Fwd Packet Length Mean'],row['Fwd Packet Length Std'],row['Bwd Packet Length Max'],row['Bwd Packet Length Min'],row['Bwd Packet Length Mean'],row['Bwd Packet Length Std'],row['Flow Bytes/s'],row['Flow Packets/s'],row['Flow IAT Mean'],row['Flow IAT Std'],row['Flow IAT Max'],row['Flow IAT Min'],row['Fwd IAT Total'],row['Fwd IAT Mean'],row['Fwd IAT Std'],row['Fwd IAT Max'],row['Fwd IAT Min'],row['Bwd IAT Total'],row['Bwd IAT Mean'],row['Bwd IAT Std'],row['Bwd IAT Max'],row['Bwd IAT Min'],row['Fwd PSH Flags'],row['Bwd PSH Flags'],row['Fwd URG Flags'],row['Bwd URG Flags'],row['Fwd Header Length'],row['Bwd Header Length'],row['Fwd Packets/s'],row['Bwd Packets/s'],row['Packet Length Min'],row['Packet Length Max'],row['Packet Length Mean'],row['Packet Length Std'],row['Packet Length Variance'],row['FIN Flag Count'],row['SYN Flag Count'],row['RST Flag Count'],row['PSH Flag Count'],row['ACK Flag Count'],row['URG Flag Count'],row['CWR Flag Count'],row['ECE Flag Count'],row['Down/Up Ratio'],row['Average Packet Size'],row['Fwd Segment Size Avg'],row['Bwd Segment Size Avg'],row['Fwd Bytes/Bulk Avg'],row['Fwd Packet/Bulk Avg'],row['Fwd Bulk Rate Avg'],row['Bwd Bytes/Bulk Avg'],row['Bwd Packet/Bulk Avg'],row['Bwd Bulk Rate Avg'],row['Subflow Fwd Packets'],row['Subflow Fwd Bytes'],row['Subflow Bwd Packets'],row['Subflow Bwd Bytes'],row['FWD Init Win Bytes'],row['Bwd Init Win Bytes'],row['Fwd Act Data Pkts'],row['Fwd Seg Size Min'],row['Active Mean'],row['Active Std'],row['Active Max'],row['Active Min'],row['Idle Mean'],row['Idle Std'],row['Idle Max'],row['Idle Min'],row['Src IP'],row['Dst IP']))
			db.commit()
			
			cursor.close()
		except MySQLdb.IntegrityError:
			print("Database insert has failed!")
		finally:
			cursor.close()
	except Exception as e:
		print(e)
	

# Function used to animate the graph
def animate(i, xs, ys, xs2, ys2):
	xs.append(datetime.now().strftime('%H:%M:%S')) # Add current time to x list for subplot 1
	ys.append(flow_count) # Add flow count to y list for subplot 1

	xs2.append(datetime.now().strftime('%H:%M:%S')) # Add current time to x list for subplot 2
	ys2.append(anomaly_count) # Add anomaly count to y list for subplot 2

	xs = xs[-20:]
	ys = ys[-20:]

	xs2 = xs2[-20:]
	ys2 = ys2[-20:]

	ax.clear() # Clear subplot 1
	ax.plot(xs, ys) # Plot the time and flow count on subplot 1

	ay.clear() # Clear subplot 2
	ay.plot(xs2, ys2) # Plot the time and anomaly count on subplot 2

	plt.xticks(rotation=45, ha='right')
	plt.subplots_adjust(bottom=0.30)

	ax.title.set_text('Flows scanned over time') # Set subplot 1 title text
	ax.set_ylabel('Flows scanned') # Set y axis label for subplot 1

	ay.title.set_text('Anomalies predicted over time') # Set subplot 1 title text
	ay.set_ylabel('Anomalies predicted') # Set y axis label for subplot 2

	ax.set_xlabel('Time')

	# Adjusting position of second subplot (moving it down a little)
	pos = ay.get_position() # Get current position of subplot
	new_pos = [pos.x0, pos.y0-0.05, pos.width, pos.height] # Compute new position (move down 0.05)
	ay.set_position(new_pos) # Set new position for subplot


# Function displays a 'splash' message stating the name of the group members and project title
def display_initial_splash():
	os.system('cls' if os.name == 'nt' else 'clear') # Use os.system to clear the screen with cls for Linux and clear for Windows
	print("----")
	print("Group 1 - Cybersecurity and Data Analytics")
	print("INTRUSION DETECTION SYSTEM")
	print("Patryk Kaiser, Daniel Mackey, Ingrid Melin")
	print("----")
	print("Awaiting flow data...")
	

if __name__ == "__main__":
	dir_path = 'TCPDUMP_and_CICFlowMeter-master/csv/' + datetime.now().strftime("%d_%m_%Y") # This is the path to the CICFlowMeter directory
	model = keras.models.load_model("cic17-cic18.h5") # Loading the saved Keras model
	label_encoder = joblib.load('label_encoder70.joblib') # Loading the label encoder from a joblib file
	event_handler = MonitorFolder() # Create new event to handle monitoring the directory
	observer = Observer() # New observer to watch csv directory
	observer.schedule(event_handler, path=dir_path, recursive=True)
	observer.start()

	display_initial_splash()

	# Displaying the live graph with Matplotlib
	fig = plt.figure() # Create the figure

	ax = fig.add_subplot(211) # First subplot (FLOWS)
	ay = fig.add_subplot(212) # Second subplot (ANOMALIES)

	xs = [] # X values list for first subplot
	ys = [] # Y Values list for first subplot

	xs2 = [] # X values list for second subplot
	ys2 = [] # Y values list for second subplot
	
	ani = animation.FuncAnimation(fig, animate, fargs=(xs, ys, xs2, ys2), interval=graph_update_interval_ms) # Call the animation function passing the figure, function arguments and the interval (in ms)
	plt.show() # Show the graph
	try:
		while(True):
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
		observer.join()
