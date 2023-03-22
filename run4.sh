#bcc
python3 src/utils/comment_extractor.py -s  ./human_annotations/human_commented_bcc/ -d ./op/bcc/commented_bcc/bcc.db_comments.db

cp op/bcc/commented_bcc/bcc.db_comments.db ./repo_db/bcc_annotated.db

#mptm
python3 src/utils/comment_extractor.py -s  ./human_annotations/human_commented_xdp-mptm-main/ -d ./op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db

cp ./op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db ./repo_db/xdp-mptm-main_annotated.db

#rate-limiter
python3 src/utils/comment_extractor.py -s  ./human_annotations/human_commented_ebpf-ratelimiter-main -d ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db

cp ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db ./repo_db/ebpf-ratelimiter-main_annotated.db

#bpf-filter
python3 src/utils/comment_extractor.py -s projects/bpf-filter/human_annotated/ -d  ./op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db

cp ./op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db projects/bpf-filter/bpf-filter-master_annotated.db


