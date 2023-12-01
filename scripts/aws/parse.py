import os
import datetime

#####################################################################
### Note: this will break if the timestamp for logging is changed ###
#####################################################################
def parse_files(path):
    datetime_fmt = '%Y-%m-%dT%H:%M:%S.%f'

    avg_difference = datetime.timedelta(seconds=0)
    counter = 0

    for filename in os.listdir(path):
        if ".log" not in filename:
            continue
        with open(os.path.join(os.getcwd(), path + filename), 'r') as f:
            prev = None
            for line in f:
                if "Beacon value:" in line:
                    timestamp = line[1:line.index("I")-2]
                    dt_object = datetime.datetime.strptime(
                        timestamp, datetime_fmt)
                    if prev is None:
                        prev = dt_object
                        continue
                    counter += 1
                    difference = dt_object - prev
                    prev = dt_object
                    avg_difference += difference

    return avg_difference, counter
