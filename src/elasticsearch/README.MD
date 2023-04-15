# Getting Started

1) Copy all annotated dbs that need to be searched into the ```dbs``` folder. 
2) Run elastic_loader.py to load annotated dbs into an elastic search backend as follows

```
python3 elastic_loader.py --help
usage: elastic_loader.py [-h] --index INDEX

Indexing elasticsearch documents.

options:
  -h, --help     show this help message and exit
  --index INDEX  Elasticsearch index name.

```
