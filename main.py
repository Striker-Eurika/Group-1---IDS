import pyshark
import pandas as pd


def monitor_to_csv(network_interface, max_rows):
    # init empty list for rows
    mylist = []
    # for filename
    count = 0
    # init capture
    capture = pyshark.LiveCapture(interface=network_interface)
    # iterate through packets from live capture
    for raw_packet in capture.sniff_continuously():
        # can throw attribute error if not tcp
        try:
            # new tcp packet just came in
            just_arrived = tcp_parse(raw_packet)
            # confirm row is valid
            if just_arrived is not None:
                # display row
                print(just_arrived)
                # append to list
                mylist.append(just_arrived)
            # save at limit
            if len(mylist) >= max_rows:
                mydf = pd.DataFrame(mylist,
                                    columns=['Destination Port', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
                                             'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
                                             'ECE Flag Count'])
                # export to csv
                pd.DataFrame.to_csv(mydf, 'monitor_data_'+str(count)+'.csv')
                count += 1
                # clear the list
                mylist.clear()
                # display head of the new df
                print(mydf.head())
        except AttributeError as error:
            print(error)
            pass


def tcp_parse(packet):
    # parse the tcp features we want
    if 'tcp' in packet:
        destination_port = packet[packet.transport_layer].dstport
        fin = packet.tcp.flags_fin
        syn = packet.tcp.flags_syn
        rst = packet.tcp.flags_reset
        psh = packet.tcp.flags_push
        ack = packet.tcp.flags_ack
        urg = packet.tcp.flags_urg
        cwe = packet.tcp.flags_cwr
        ece = packet.tcp.flags_ece
        data = [destination_port, fin, syn, rst, psh, ack, urg, cwe, ece]
        if data is not None:
            return data


if __name__ == "__main__":
    monitor_to_csv('wlp3s0', 20)
    """
    df = pd.read_csv('NewMachineLearningLabels.csv')
    # print(list(df.columns.values))
    cols = list(df.columns.values)[1:]
    print(cols)
    col_names = [i.strip(' ') for i in cols]
    print(col_names)
    """
