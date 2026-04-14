import csv
from typing import Set
import os

def entryGuards() -> Set[str]:
    try:
        tor_ips = set()
        
        # Use relative path instead of hardcoded absolute path
        csv_file = os.path.join(os.path.dirname(__file__), 'latest.guards.csv')
        
        with open(csv_file, 'r') as file:
            reader = csv.reader(file)
            
            for count, row in enumerate(reader):
                if count >= 100:
                    break
                if row: # Ensure the row isn't blank
                    tor_ips.add(row[0]) # Grab the first column and add to the Set
                    
        return tor_ips

    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return set() # Return an empty set so the sniffer doesn't crash