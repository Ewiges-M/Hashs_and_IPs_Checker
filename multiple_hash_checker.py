import requests
import time
import csv
import json
start_time = time.time()
total_data_to_csv = []
HYBRID_ANALYSIS_URL = "https://hybrid-analysis.com/api/v2/overview/"
IP_INFO_URL = "http://ipinfo.io/"

def connectToHybridAnalysis(hash,hybrid_analysis_key):
        try:
        
            url = HYBRID_ANALYSIS_URL
            apikey = str(hybrid_analysis_key)
            response = requests.get(url+hash, headers={ 'accept': 'application/json' , 'user-agent': 'Falcon Sandbox' , 'api-key': apikey})
            result = response.json()
            api_limit = json.loads(response.headers['Api-Limits'])
            
            print("Current API Limit in minute : "+ str(api_limit['used']['minute']) +" / "+ str(api_limit['limits']['minute']))
            print("Current API Limit in hour : "+ str(api_limit['used']['hour']) +" / "+ str(api_limit['limits']['hour']))
            
            md_score = ""
            vt_score = ""
            cs_percent = ""
            md_percent = ""
            md_total = ""
            vt_percent = ""
            vt_total = ""
            file_type = result['type']
            AV_Detection = result['multiscan_result']
            verdict = result['verdict']

            if api_limit['limit_reached'] != 'true':
                for index , scanner in enumerate(result['scanners']):
                    
                    name = result['scanners'][index]['name']
                    
                    if (name.find('CrowdStrike')) != -1:
                        cs_percent = result['scanners'][index]['percent']
                    if name == 'Metadefender':
                        md_score = str(result['scanners'][index]['positives'])
                        md_total = str(result['scanners'][index]['total'])
                        md_percent = result['scanners'][index]['percent']
                    if name == "VirusTotal":
                        vt_score = str(result['scanners'][index]['positives']) 
                        vt_total = str(result['scanners'][index]['total'])
                        vt_percent = result['scanners'][index]['percent']    
                                
                data = [hash,file_type,verdict,AV_Detection,cs_percent,vt_score,vt_total,vt_percent,md_score,md_total,md_percent]
                total_data_to_csv.append(data)
            else: 
                print("Your API limit has been reached")
                exit()
                 
        except:
            print(result['message'])
            data = [hash,"N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A"]
            total_data_to_csv.append(data)
        
def writeToFile():
    header = ['IOCs', 'File Type' , 'Verdict' ,'AV_Detection', 'CrowdStrike Percent', 'Virustotal Positives', 'Virustotal Total', 'Virustotal Percent', 'Metadefender Positives', 'Metadefender Total','Metadefender Percent']

    with open('Hash_IOCs_results.csv', 'w', encoding='UTF8', newline='') as f:
        print("writing data to file Hash_IOCs_results.csv ...")
        writer = csv.writer(f)

        # write the header
        writer.writerow(header)

        # write multiple rows
        writer.writerows(total_data_to_csv)
    print("Succussful write data to file Hash_IOCs_results.csv")
    
def main():
    try:
        print("Reading Initial file init.json")
        init_file = open('init.json',)
        initial_data = json.load(init_file)
        print("Retrieve data from hash-list.txt")
        
        with open('hash-list.txt', 'r') as file:
            data = file.read().replace('\n', ',')
            list_hash = data.split(',')
            
        for index , list_hash in enumerate(list_hash):
            if list_hash != "":
                
                print("No.",index,"IOCs :",list_hash)
                print(initial_data['HYBRID_ANALYSIS_API_KEY'])
                connectToHybridAnalysis(list_hash.strip(),str(initial_data['HYBRID_ANALYSIS_API_KEY']))
                time.sleep(0.5)
                
        writeToFile()
        
    except:
        
        print("Can not found file init.json or hash-list.txt")
    
    print("--- %s seconds ---" % (time.time() - start_time))
    
main()
