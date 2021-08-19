import requests
import time
import csv
import re
import json
start_time = time.time()
total_data_to_csv = []
VIRUS_TOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"
IP_INFO_URL = "http://ipinfo.io/"


def connectToVirustotal(ip,VT_key,IP_info_key):
        try:
            
            url = VIRUS_TOTAL_URL

            params = {'apikey': str(VT_key), 'resource': ip}

            response = requests.get(url, params=params)
            
            result = response.json()

            isIP = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
            if isIP:
                print (ip + " Checking with Virustotal and IPinfo ...")
                if result["response_code"] == 1:
                    positives_tools = str(result["positives"])
                    total_tools = str(result["total"])
                    detected_tools = result['scans']
                    detected_as_malware_site = []
                    detected_as_malicious_site = []
                    detected_as_suspicious_site = []
                    
                    response_form_ip_info = requests.get(IP_INFO_URL + ip+ '/json?token='+IP_info_key)
                    result_form_ip_info = response_form_ip_info.json()
                    
                    for key in detected_tools.keys():
                        resultScan = detected_tools[key]['result']
                        if resultScan == 'malware site':
                            detected_as_malware_site.append(key)
                            
                        elif resultScan == 'malicious site':
                            detected_as_malicious_site.append(key)
                            
                        elif resultScan == 'suspicious site':
                            detected_as_suspicious_site.append(key)
                            
                    data = [ip,result_form_ip_info['country'],result_form_ip_info['org'],positives_tools,total_tools,', '.join(detected_as_malware_site),', '.join(detected_as_malicious_site),', '.join(detected_as_suspicious_site)]
                    total_data_to_csv.append(data)
                else:
                    print(ip + " was not present in VirusTotal's dataset")
                    data = [ip, 'N/A', 'N/A', 'N/A', 'N/A', 'N/A' , 'N/A', 'N/A']
                    total_data_to_csv.append(data)
            else:
                print (ip + " Checking with Virustotal ...")
                if result["response_code"] == 1:
                    positives_tools = str(result["positives"])
                    total_tools = str(result["total"])
                    detected_tools = result['scans']
                    detected_as_malware_site = []
                    detected_as_malicious_site = []
                    detected_as_suspicious_site = []
                    for key in detected_tools.keys():
                        resultScan = detected_tools[key]['result']
                        if resultScan == 'malware site':
                            detected_as_malware_site.append(key)
                            
                        elif resultScan == 'malicious site':
                            detected_as_malicious_site.append(key)
                            
                        elif resultScan == 'suspicious site':
                            detected_as_suspicious_site.append(key)
                                
                    data = [ip,"N/A","N/A",positives_tools,total_tools,', '.join(detected_as_malware_site),', '.join(detected_as_malicious_site),', '.join(detected_as_suspicious_site)]
                    total_data_to_csv.append(data)
                else:
                    print(ip + " was not present in VirusTotal's dataset")
                    data = [ip, 'N/A', 'N/A', 'N/A', 'N/A', 'N/A' , 'N/A', 'N/A']
                    total_data_to_csv.append(data)
            
        except:
            print(ip + " Can't connect to Virustotal")

def writeToFile():
    header = ['IOCs', 'Country' , 'ORG' ,'Positives', 'Totals', 'Detected as Malware site', 'Detected as Malicious site', 'Detected as Suspicious site']

    with open('URL&IP_IOCs_results.csv', 'w', encoding='UTF8', newline='') as f:
        print("writing data to file URL&IP_IOCs_results.csv ...")
        writer = csv.writer(f)

        # write the header
        writer.writerow(header)

        # write multiple rows
        writer.writerows(total_data_to_csv)
    print("Succussful write data to file URL&IP_IOCs_results.csv")
    
def main():
    try:
        print("Reading Initial file init.json")
        init_file = open('init.json',)
        initial_data = json.load(init_file)
        print("Retrieve data from ip-list.txt")
        
        with open('ip-list.txt', 'r') as file:
            data = file.read().replace('\n', ',')
            list_ip = data.split(',')
        for index , list_ip in enumerate(list_ip):
            print("No.",index,"IOCs :",list_ip)
            connectToVirustotal(list_ip.strip(),initial_data['VIRUSTOTAL_API_KEY'],initial_data['IP_INFO_TOKEN'])
            time.sleep(15)
        writeToFile()
        
    except:
        print("Can not found file init.json or ip-list.txt")
        
    
    print("--- %s seconds ---" % (time.time() - start_time))
   
main()



    
