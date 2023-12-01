IP_FILE=${2:-"ips.txt"}
IPS=()

while IFS= read -r line; do
  IPS+=($line)
done < $IP_FILE

idx=0

for ip in "${IPS[@]}"
do
    ssh -i "randpiper.pem" -t ubuntu@$ip 'bash -ls --' < scripts/aws/test.sh $idx &
    idx=$(($idx+1))
done

wait

idx=0

for ip in "${IPS[@]}"
do
  scp -i "randpiper.pem" ubuntu@$ip:grandline/output.log ./logs/$idx.log &
  idx=$(($idx+1))
done

wait