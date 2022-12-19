import subprocess
import os
from datetime import datetime

# Path to TCPDUMP CICFLOWMETER
path_to_cicflowmeter = os.getcwd() + '/TCPDUMP_and_CICFlowMeter-master/'

# Command to execute
# Here I am running the TCPDUMP CICFLOWMETER .sh file and passing basic commands such as the adapter...
run_command = './capture_interface_pcap.sh'

interface = 'wlp3s0'

# Directory for new capture flow
dir_path = path_to_cicflowmeter + 'csv/' + datetime.now().strftime("%d_%m_%Y")

# Create the directory
if not os.path.exists(dir_path):
	os.mkdir(dir_path)

dir_path = dir_path

# Run TCP DUMP
subprocess.call(['bash',path_to_cicflowmeter + run_command, interface, dir_path, 'patryk'])
