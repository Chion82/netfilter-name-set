iptables -A INPUT -i enp0s3 -j NAMESET --hook-dns-response
iptables -A OUTPUT -o enp0s3 -m nameset --match-set testset --nameset-dst
iptables -A OUTPUT -o enp0s3 -m nameset --match-set anotherset --nameset-dst
