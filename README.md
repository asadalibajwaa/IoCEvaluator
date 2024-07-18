# IoCEvaluator
This repository allows you to extract IoCs from text reports and evaluate their quality.

  # IoC Extraction
We use open source extrator CyNER to extract IoCs from text reports. We also provide a simple python script (extract_IoCs.py) using regex to extract the IoCs first and save them in a csv file.

  # IoC Weighted Verdict
Run the file Weighted_Verdict.py to get Overall verdict for the IoCs (IP addresses) saved in the ip_addresses_2.csv file. The results are saved in the ip_verdicts_2.csv file
