# Multiple Hash ( Sha256 ) and URL Checker with Virustotal and Hybrid Analysis

This Program used for analysis multiple URL/IP by Virustotal and analysis multiple hash with Hybrid Analysis then create report result to you with clearly format.
If you have tons of IOCs this program can help you for reducing analysis time. You can quickly filter out the clean artifacts and have more time to focus with real IOCs.

## Features
- Check multiple URL/IP with [Virustotal](https://www.virustotal.com/) then list result to csv file.
- Check IP Geolocation with [ipinfo](https://ipinfo.io/)
- Check multiple Hash( only SHA256 ) with [Hybrid Analysis](https://www.hybrid-analysis.com/) then list result to csv file.

## Getting started

1. Put API keys of Virustotal, IPinfo and Hybrid Analysis to file **init.json**.

```
{
    "VIRUSTOTAL_API_KEY": "",
    "IP_INFO_TOKEN" : "",
    "HYBRID_ANALYSIS_API_KEY" : ""

}
```

2. Put list of hash (separate each hash newline) to file **hash-list.txt**

Example
```
20831e820af5f41353b5afab659f2ad42ec6df5d9692448872f3ed8bbb40ab92
225e9596de85ca7b1025d6e444f6a01aa6507feef213f4d2e20da9e7d5d8e430
392f32241cd3448c7a435935f2ff0d2cdc609dda81dd4946b1c977d25134e96e
40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b
```

3. Put list of URL/IP (separate each hash newline) to file **ip-list.txt**

Example
```
www.example.com
8.8.8.8
www.google.com
1.1.1.1
```
## How to get API Key

- [Hybrid Analysis API Key](https://www.hybrid-analysis.com/docs/api/v2)

- [Virustotal Api Key](https://developers.virustotal.com/v3.0/reference#public-vs-premium-api)

- For IPINFO go to [IPinfo](https://ipinfo.io/) then register, login and select Token button as the picture below.

<img width="1239" alt="Screen Shot 2564-08-20 at 00 18 24" src="https://user-images.githubusercontent.com/70726596/130114477-7ce9bd98-672e-4875-b5ec-04e94fbe41d6.png">


## Usage

For URL/IP

```
python3 multiple_ip_checker.py
```

For Hash

```
python3 multiple_hash_checker.py
```

## Result

**Hash_IOCs_results.csv**

![image](https://user-images.githubusercontent.com/70726596/130112177-4d3f79fb-7d03-4157-b418-3fd01a2ed0b7.png)

**URL/IP_IOCs_results.csv**

![image](https://user-images.githubusercontent.com/70726596/130115178-b6db7847-0ea8-498d-89c3-ddce3e605bb6.png)

## Requirements
- Python version 3 and higher

## API Limit

- Virustotal API Key (free user) : 500 API requests per day and a rate of 4 API requests per minute.

- IPinfo Token (free user) : 50,000 API requests per month.

- Hybrid Analysis API Key (free user) : 200 API requests per minute and 2,000 API requests per hour.
