# nvi-api-documentation
API documentation to access NVI Vulnerability Intelligence


This API allows users to retrieve vulnerability intelligence information from NVI platform. https://ww.northinfosec.com

Endpoint

URL https:/service.northinfosec.com

POST /api/

Headers

	•	Authorization Token: This API requires an authorization token to be passed in the request header.
	•	Header Name: token
	•	Type: String
	•	Required: Yes
	•	Description: The API key generated after registration under details at https://www.northinfosec.com

Request Body

The request body should be a JSON object containing a list of CVE IDs.

	•	cveid: A list of CVE IDs that you want information about.
	•	Type: Array of strings
	•	Required: Yes
	•	Example:
 
 ```
{
  "cveid": ["CVE=2024-38440", "CVE-2024-37334"]
}
 ```
Response

The API will return a JSON object containing details about each CVE ID in the request.

	•	Success Response:
	•	Status Code: 200 OK
	•	Body: A JSON object with information about the CVEs.
	•	Example:

 ```

 [
    {
        "cveID": "CVE-2024-37334",
        "cvss3": 8.8,
        "description": "Microsoft OLE DB Driver for SQL Server Remote Code Execution Vulnerability",
        "detailed_recommendation": "NVI Analysts have not posted a custom recommendation. Please reach out if you need it and we will get back to you ASAP. nvi@northinfosec.com",
        "epss": 0.00133,
        "exploit_classification": "RCE",
        "exploit_lc": "None",
        "kev": "No",
        "ransomware": "No",
        "risk_rating": "Medium",
        "risk_score": "45"
    },
    {
        "cveID": "CVE-2024-38440",
        "cvss3": 7.3,
        "description": "Netatalk before 3.2.1 has an off-by-one error, and resultant heap-based buffer overflow and segmentation violation, because of incorrectly using FPLoginExt in BN_bin2bn in etc/uams/uams_dhx_pam.c. The original issue 1097 report stated: 'The latest version of Netatalk (v3.2.0) contains a security vulnerability. This vulnerability arises due to a lack of validation for the length field after parsing user-provided data, leading to an out-of-bounds heap write of one byte (\\0). Under specific configurations, this can result in reading metadata of the next heap block, potentially causing a Denial of Service (DoS) under certain heap layouts or with ASAN enabled. ... The vulnerability is located in the FPLoginExt operation of Netatalk, in the BN_bin2bn function found in /etc/uams/uams_dhx_pam.c ... if (!(bn = BN_bin2bn((unsigned char *)ibuf, KEYSIZE, NULL))) ... threads ... [#0] Id 1, Name: \"afpd\", stopped 0x7ffff4304e58 in ?? (), reason: SIGSEGV ... [#0] 0x7ffff4304e58 mov BYTE PTR [r14+0x8], 0x0 ... mov rdx, QWORD PTR [rsp+0x18] ... afp_login_ext(obj=<optimized out>, ibuf=0x62d000010424 \"\", ibuflen=0xffffffffffff0015, rbuf=<optimized out>, rbuflen=<optimized out>) ... afp_over_dsi(obj=0x5555556154c0 <obj>).' 2.4.1 and 3.1.19 are also fixed versions.",
        "detailed_recommendation": "NVI Analysts have not posted a custom recommendation. Please reach out if you need it and we will get back to you ASAP. nvi@northinfosec.com",
        "epss": 0.00045,
        "exploit_classification": "RCE",
        "exploit_lc": "None",
        "kev": "No",
        "ransomware": "No",
        "risk_rating": "Medium",
        "risk_score": "40"
    }
]
 ```
Example Curl Request
```
curl -X POST https:/service.northinfosec.com/api \
-H "Content-Type: application/json" \
-H "token: YOUR_API_KEY_HERE" \
-d '{
    "cveid": ["CVE-2024-38440", "CVE-2024-37334"]
}'
```






