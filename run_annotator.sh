#katran
python3 src/annotator.py -o op/katran/txl_katran -s projects/katran/original_source/ -c projects/katran/commented_katran -t op/katran/katran.function_file_list.json -u op/katran/katran.struct_file_list.json -p katran -d projects/katran/boston_katran_comments.json

#cilium
python3 src/annotator.py -o op/cilium/txl_cilium -s projects/cilium/original_source/ -c op/cilium/commented_cilium -t op/cilium/cilium.function_file_list.json -u op/cilium/cilium.struct_file_list.json --isCilium -p cilium -d projects/cilium/boston_cilium_comments.json

#bcc
python3 src/annotator.py -o op/bcc/txl_bcc -s projects/bcc/original_source/ -c op/bcc/commented_bcc -t op/bcc/bcc.function_file_list.json -u op/bcc/bcc.struct_file_list.json  -p bcc

#mptm
python3 src/annotator.py -o op/xdp-mptm-main/txl_xdp-mptm-main -s projects/mptm/original_source/src/kernel  -c op/xdp-mptm-main/commented_xdp-mptm-main -t op/xdp-mptm-main/xdp-mptm-main.function_file_list.json -u op/xdp-mptm-main/xdp-mptm-main.struct_file_list.json -p xdp-mptm-main

#ratelimiter
python3 src/annotator.py -o op/ebpf-ratelimiter-main/txl_ebpf-ratelimiter-main -s projects/rate-limiter/original_source/ -c op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main -t op/ebpf-ratelimiter-main/ebpf-ratelimiter-main.function_file_list.json -u op/ebpf-ratelimiter-main/ebpf-ratelimiter-main.struct_file_list.json -p ebpf-ratelimiter-main

#bpf-filter
python3 src/annotator.py -o op/bpf-filter-master/txl_bpf-filter-master -s projects/bpf-filter/original_source/ebpf/ -c op/bpf-filter-master/commented_bpf-filter-master -t op/bpf-filter-master/bpf-filter-master.function_file_list.json -u op/bpf-filter-master/bpf-filter-master.struct_file_list.json -p bpf-filter-master



#python3 src/annotator.py -o op/kpng-master/txl_kpng-master -s examples/kpng-master/backends/ebpf/bpf -c op/kpng-master/commented_kpng-master -t op/kpng-master/kpng-master.function_file_list.json -u op/kpng-master/kpng-master.struct_file_list.json -p kpng-master

#python3 src/annotator.py -o op/ingress-node-firewall-master/txl_ingress-node-firewall-master -s examples/ingress-node-firewall-master/bpf -c op/ingress-node-firewall-master/commented_ingress-node-firewall-master -t op/ingress-node-firewall-master/ingress-node-firewall-master.function_file_list.json -u op/ingress-node-firewall-master/ingress-node-firewall-master.struct_file_list.json -p ingress-node-firewall-master

#python3 src/annotator.py -o op/netobserv-bpf-main/txl_netobserv-bpf-main -s examples/netobserv-bpf-main -c op/netobserv-bpf-main/commented_netobserv-bpf-main -t op/netobserv-bpf-main/netobserv-bpf-main.function_file_list.json -u op/netobserv-bpf-main/netobserv-bpf-main.struct_file_list.json -p netobserv-bpf-main

#python3 src/annotator.py -o op/suricata-master/txl_suricata-master -s examples/ -c op/suricata-master/commented_suricata-master -t op/suricata-master/suricata-master.function_file_list.json -u op/suricata-master/suricata-master.struct_file_list.json -p suricata-master

#python3 src/annotator.py -o op/vpf-ebpf-src/txl_vpf-ebpf-src -s examples/vpf-ebpf-src -c op/vpf-ebpf-src/commented_vpf-ebpf-src -t op/vpf-ebpf-src/vpf-ebpf-src.function_file_list.json -u op/vpf-ebpf-src/vpf-ebpf-src.struct_file_list.json -p vpf-ebpf-src


