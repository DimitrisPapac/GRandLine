IP_FILE=${2:-"ips.txt"}
IP_AWS_FILE=${2:-"scripts/aws/ips"}
IPS=()

while IFS= read -r line; do
  IPS+=($line)
done < $IP_FILE

for ip in "${IPS[@]}"
do
    echo $ip
    ssh -i "randpiper.pem" -o "StrictHostKeyChecking no" -t ubuntu@$ip 'bash -ls' < scripts/aws/setup.sh &
done

wait

for ip in "${IPS[@]}"
do
  echo $ip
  ssh -i "randpiper.pem" ubuntu@$ip "cd grandline; cat > ips.txt" < $IP_AWS_FILE &
done

wait