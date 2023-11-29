cargo build --bin app --release

RUNTIME=30

FILE="${1:-/dev/stdin}"
IPS=()

while IFS= read -r line; do
  IPS+=($line)
done < $FILE

idx=0

for ip in "${IPS[@]}"
do
    ./target/release/app $idx ips &> logs/$idx.log&
    idx=$(($idx+1))
done

sleep $RUNTIME
killall -9 app