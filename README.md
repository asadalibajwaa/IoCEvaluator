# IoCEvaluator
This repository allows you to extract IoCs from text reports and evaluate their quality.

## IoC Extraction
We use open source extrator CyNER to extract IoCs from text reports. We also provide a simple python script (extract_IoCs.py) using regex to extract the IoCs first and save them in a csv file. We provide a sample CTI report in text format included in the extract_IoCs.py file. You can replace it with your own text to extract IoCs.

## IoC Weighted Verdict_General
Run the file Weighted_Verdict_Genral.py to get Overall verdict for the IoCs (IP addresses, Hashes, domains, URLs) saved in the your csv file. This csv file is obtained as a result of running the extract_IoCs.py that extracts all IoCs from the provided report.

## IoC Weighted Verdict_IP
This is for the test. Run the file Weighted_Verdict.py to get Overall verdict for the IoCs (IP addresses) saved in the ip_addresses_2.csv file. The results are saved in the ip_verdicts_2.csv file
