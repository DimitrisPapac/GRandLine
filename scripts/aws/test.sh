killall -9 app
cd grandline
timeout 300 ./target/release/app $1 ips.txt 2 &> output.log