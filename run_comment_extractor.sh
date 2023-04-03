#bcc
python3 src/utils/comment_extractor.py -s  projects/bcc/human_annotated/ -d ./op/bcc/commented_bcc/bcc.db_comments.db

cp op/bcc/commented_bcc/bcc.db_comments.db projects/bcc/bcc_annotated.db

#mptm
python3 src/utils/comment_extractor.py -s  projects/mptm/human_annotated/ -d ./op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db

cp op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db ./projects/mptm/xdp-mptm-main_annotated.db

#rate-limiter
python3 src/utils/comment_extractor.py -s  projects/rate-limiter/human_annotated/  -d ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db

cp ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db projects/rate-limiter/ebpf-ratelimiter-main_annotated.db

#bpf-filter
python3 src/utils/comment_extractor.py -s projects/bpf-filter/human_annotated/ -d  ./op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db

cp ./op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db projects/bpf-filter/bpf-filter-master_annotated.db


#suricata
python3 src/utils/comment_extractor.py -s projects/suricata-master/human_annotated/ -d  projects/suricata-master/human_annotated/suricata-master.db_comments.db

#netobserv
python3 src/utils/comment_extractor.py -s projects/netobserv-bpf-main/human_annotated -d  projects/netobserv-bpf-main/human_annotated/netobserv-bpf-main.db_comments.db
