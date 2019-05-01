# Instructions

These have been tested on a Macbook.

1. Update `/etc/pf.conf` with the following lines:
```
block drop proto tcp from port 50000 to any flags R/R
block drop proto tcp from port 50001 to any flags R/R
block drop proto tcp from port 50002 to any flags R/R
block drop proto tcp from port 50003 to any flags R/R
block drop proto tcp from port 50004 to any flags R/R
```
2. Run the following commands:
```
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

3. Run `pip install -r requirements.txt`

4. To run the full list of experiments, run the following:
```sudo python -u measure_icw.py --mss 100 --input_file servers.txt --timeout=10 --logfile mss_100.json
sudo python -u measure_icw.py --mss 536 --input_file servers.txt --timeout=10 --logfile mss_536.json```

5. To produce the data for the tables and graph included in the paper, run the following:
```python process_results.py -l mss_100.json --mss 100
python process_results.py -l mss_536.json --mss 536```
