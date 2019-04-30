# Instructions

1. Update `/etc/pf.conf` with the following lines:
```
block drop proto tcp from port 50000 to any flags R/R
block drop proto tcp from port 50001 to any flags R/R
block drop proto tcp from port 50002 to any flags R/R
block drop proto tcp from port 50003 to any flags R/R
block drop proto tcp from port 50004 to any flags R/R
```
2. To run the full list of experiments, run the following:
`sudo python -u measure_icw.py --mss 100 --input_file servers.txt --timeout=10 --verbose | tee results.log`
