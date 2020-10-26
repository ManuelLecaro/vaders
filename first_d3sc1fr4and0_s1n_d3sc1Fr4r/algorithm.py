import argparse
import os
import sys
import cryptography
import socket
import ipaddress
from scapy.all import *
import pandas as pd
import numpy as np

from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances_argmin_min
from sklearn.ensemble import IsolationForest
from sklearn.covariance import EllipticEnvelope
from sklearn import preprocessing

load_layer("tls")

def process_pcap(file_name, domain):
    print('Opening {}... checking traffic on {}'.format(file_name, domain))
    extract_data(file_name, domain)


def extract_data(file_name, domain):
    client = socket.gethostbyname(domain)
    print('domain ip is: ' + client)
    
    count = 0

    data_list = []
    pkts = rdpcap(file_name)
    for package in pkts:
        if("TLS" in package):
            fuente = ''
            local_list = []
            if ("IP" in package):
                count +=1
                fuente = package['IP'].src
                dest = package['IP'].dst
                if(fuente == client or dest == client):
                    window = package.window
                    size = package['TLS'].len
                    #print('{} Fuente {}, destino {} ... ventana on {} size on {}'.format(count, fuente, dest, window, size))
                    local_list = [fuente, fuente, dest, fuente == client, dest == client, window, size]
                    data_list.append(local_list)
    df = pd.DataFrame(data_list, columns=['ip', 'fuente','destino', 'is_dom_src', 'is_dom_dest', 'window', 'size'])
    analize_data(df)
    

def analize_data(data):
    #1 First get the packets with less data size and take them as 
    data.ip = pd.Categorical(data.ip).codes
    X = np.array(data[['ip', 'window', 'size']])
    min_max_scaler = preprocessing.MinMaxScaler()
    x_scaled = min_max_scaler.fit_transform(X)
    X = pd.DataFrame(x_scaled)
    
    ee = EllipticEnvelope(contamination=0.01)
    iso = IsolationForest(contamination=0.1, random_state=0)
    yhat = iso.fit_predict(X)
    count = 0
    isolated = []
    for i in yhat:
        if(i==-1):
            isolated.append(count)
        count += 1
    # select all rows that are outliers, that means that value is -1
    data = data.ix[isolated]
    X = np.array(data[['ip', 'window', 'size']])
    yhat = ee.fit_predict(X)
    
    data['size']=(data['size']-data['size'].min())/(data['size'].max()-data['size'].min())
    data['pctile'] = data.groupby('ip')['size'].rank(pct=True, method='average')
    data.index = pd.RangeIndex(1, len(data.index) + 1)
    
    count = 1
    second_isolation = []
    for i in yhat:
        if(i==-1):
            second_isolation.append(count)
        count += 1
    
    if(not data["ip"].is_unique):
        if(len(second_isolation) == 0):
            data = data[ (data.pctile> 0.67)& (data.size>0)]
        else:
            data = data.ix[second_isolation]
            data = data[(data.pctile> 0.67) & (data.size>0)]

    data = data.groupby("ip").max()
    print('Las ips que pudieron enviar datos en forms son.....')
    count = 1
    ips = np.where(data['is_dom_src'], data['destino'], data['fuente'])
    
    for i in ips:
        print(i)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--domain', metavar='<domain name>',
                        help='domain to check phishing', required=False)
    args = parser.parse_args()
    domain = '192.168.0.6'
    file_name = args.pcap

    if not args.domain is None:
        print('here')
        domain = args.domain
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name, domain)
    sys.exit(0)