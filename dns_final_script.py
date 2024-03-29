import pandas as pd
import os
import glob
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder
import pickle as pkl
import ipaddress
from ipaddress import ip_address
import datetime as dt
import zat
from zat.log_to_dataframe import LogToDataFrame

print('imported All required Libraries')

path = '/opt/zeek/spool/zeek/*.log'
csv_files = glob.glob(os.path.join(path))
arr=[]

try:
    print('Zeek logs File Path Found Succesfully')
    for f in csv_files:
        r=f.split('\\')[-1] 
        m = r.split('.')[0]
        arr.append(f)
    print(arr)
except Exception as e:
    print(f"Error occurred while reading file path: {e}")
    exit()

route='/opt/zeek/spool/zeek/'

def value_change(dataframe,column,value):
    try:
        dataframe[column] = dataframe[column].cat.add_categories([0,1])
            
        dataframe[column].where(dataframe[column]==value, 0, inplace=True) # replace where condition is False
        dataframe[column].mask(dataframe[column]==value, 1, inplace=True)
    except Exception as e:
        print(f"Error occurred while changing column values: {e}")
        exit()

    
def Ip_To_int(ip):
    arr=[]
    try:
        for i in ip:
            if  type(ip_address(str(i))) is ipaddress.IPv4Address:
                r=int(ipaddress.IPv4Address(str(i)))
            if type(ip_address(str(i))) is ipaddress.IPv6Address:
                r=int(ipaddress.IPv6Address(str(i)))
            arr.append(r)    
        return arr
    except Exception as e:
        print(f"Error occurred while converting IP addresses: {e}")
        exit()

try:
    log_to_df = LogToDataFrame()
    print("Starting Files Data Loading")
    for i in arr:
        if i=='/opt/zeek/spool/zeek/dns.log':
            dns_log = log_to_df.create_dataframe(route+"dns.log")
            dns_log= dns_log.dropna()
            dns_threshold = 5000
            dns_query_counts = dns_log['query'].value_counts()
            suspicious_dns_queries = dns_query_counts[dns_query_counts > dns_threshold].index
            print('DNS Load Succesfully')
        if i=='/opt/zeek/spool/zeek/conn.log':
            conn_log = log_to_df.create_dataframe(route+"conn.log")
            conn_log=conn_log.dropna()
            conn_log['dns_connection'] = (conn_log['proto'] == 'udp') & (conn_log['id.resp_p'] == 53)
            print('Conn Load Succesfully')
        if i=='/opt/zeek/spool/zeek/weird.log':
            weird_log=log_to_df.create_dataframe(route+"weird.log")
            weird_log= weird_log.dropna()
            weird_log['large_dns_query_count'] = weird_log['name'].str.startswith('dns_large_query_count')
            weird_dns_log = weird_log[weird_log['large_dns_query_count']]
            weird_dns_log['domain'] = weird_dns_log['name'].str.split('_').str[-1]
            weird_dns_query_counts = weird_dns_log['domain'].value_counts() 
            weird_dns_threshold = 10000
            suspicious_weird_domains = weird_dns_query_counts[weird_dns_query_counts > weird_dns_threshold].index
            print('Weird Load Succesfully')
except Exception as e:
    print(f"Error occurred while loading log files:{e}")
    exit()
print('Start Data Preprocessing')

try:
    merged_log = pd.merge(dns_log, conn_log, on=['id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto'], how='outer')
    merged_log = pd.merge(merged_log, weird_dns_log, on=['id.orig_h','id.orig_p','id.resp_h','id.resp_p'], how='outer')
    merged_log = merged_log.loc[:, ['id.orig_h','id.orig_p','id.resp_h','id.resp_p','query','proto','dns_connection']]
    merged_log['id.orig_h'] = Ip_To_int(merged_log['id.orig_h'])
    merged_log['id.resp_h'] = Ip_To_int(merged_log['id.resp_h'])
    merged_log['query'] = merged_log['query'].astype('category')
    merged_log['query'] = merged_log['query'].cat.set_categories([1, 0])
    merged_log['query'] = merged_log['query'].fillna(0)
    merged_log.loc[merged_log['query'] != 1, 'query'] = 0
    merged_log['dns_connection'] = merged_log['dns_connection'].fillna(False)
    merged_log['query'] = merged_log['query'].cat.add_categories(['0','1'])
    value_change(merged_log,'proto','udp')
    merged_log.to_csv('data.csv')
except Exception as e:
    print(f"Error occurred during data preprocessing: {e}")
    exit()

print('Start Model Prediction')

try:
    df=pd.read_csv('data.csv',usecols=['id.orig_h','id.orig_p','id.resp_h','id.resp_p','query','proto','dns_connection'])
    filename = 'DNS_model.sav'
    model = pkl.load(open(filename, 'rb'))
    merged_log['label'] = model.predict(df)
    print('Prediction Complete Successfully ')
    merged_log.to_csv('dns_model_prediction.csv')
    print('Prediction Saved Successfully ')
except Exception as e:
    print(f"Error occurred during model prediction: {e}")
    exit()