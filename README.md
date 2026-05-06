# 1. Install dependencies
pip install -r requirements.txt

# 2. Full reconnaissance cycle
python specter.py -d target.com --all

# 3. Subdomain brute with custom wordlist
python specter.py -d target.com --subs -w subs.txt

# 4. Single module execution
python specter.py -d target.com --ssl

# 5. Output files generated in working directory:
#    target.com_report.json
#    target.com_report.html
