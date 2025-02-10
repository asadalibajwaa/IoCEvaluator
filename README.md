# IoCEvaluator
This repository allows you to extract IoCs from text reports and evaluate their quality.

## IoC Extraction
We use open source extrator CyNER to extract IoCs from text reports. We also provide a simple python script (extract_IoCs.py) using regex to extract the IoCs first and save them in a csv file. We provide a sample CTI report in text format included in the extract_IoCs.py file. You can replace it with your own text to extract IoCs.

## IoC Verdict
### IoC Weighted Verdict_General
Run the file Weighted_Verdict_Genral.py to get Overall verdict for the IoCs (IP addresses, Hashes, domains, URLs) saved in the your csv file. This csv file should contain all the IoCs that you extracted as a result of running the extract_IoCs.py that extracts all IoCs from the provided report.

## IoC Evaluation
Run the files AV_Evaluation_General.py, VT_Evaluation_General.py, and MD_Evaluation_General.py to get the completeness, freshness, and relevance results for your IoCs.

## IoC Verdict Results
We provide the verdicts for 600 of IoCs provided by 3 CTI platforms along with the weighted verdict in file All_IoC_verdicts.xlsx.
