import argparse
from elasticsearch import Elasticsearch
import json
from elasticsearch.helpers import bulk
import os


def load_annotated_db(paths):
    docs = []
    #paths = ["cilium_annotated.db","katran_annotated.db","bpf-filter-master_annotated.db"]
    #paths= ["dbs/xdp-mptm-main_annotated.db"]
    #paths = ["bcc_annotated.db", "cilium_annotated.db","katran_annotated.db", "bpf-filter_annotated.db",       "ebpf-ratelimiter_annotated.db", "xdp-mptm-main_annotated.db"]
#["cilium_annotated.db","katran_annotated.db","xdp-mptm-main_annotated.db","bpf-filter-master_annotated.db","ebpf-ratelimiter-main_annotated.db"]
    for path in paths:
        f = open(path)
        data = json.load(f)
        print("PATH: "+path)
        commented_ct = 0
        fn_ct = 0
        empty_ct = 0
        for k in data["_default"].keys():
            try:
                full_desc = data["_default"][k]
                print("full_desc")
                print(full_desc)
                docs.append(full_desc)
                fn_ct = fn_ct + 1
                
                human_descs  = full_desc["humanFuncDescription"]
                #print("Human Descs")
                #print(human_descs)
                for desc_json in human_descs:
                    #print("desc_json")
                    #print(desc_json)
                    #t = json.loads(json.dumps(desc_json))
                    #print("TEXT: ")
                    #print(t)
                    #print("DESCRIPTION")
                    #print(t[0]["description"])
                    if "description" in desc_json:
                        #print("description")
                        #print(desc_json["description"])
                        desc = desc_json["description"]
                        if desc != "":
                            print("non empty desc: " + desc)
                            commented_ct = commented_ct + 1
                        else:
                            empty_ct = empty_ct + 1
                            print("NO Desc: "+desc)
                    #print("\n\n")
                
            except Exception as  e:
                print("Exception")
                print(e)
                continue
        print("SUMMARY PATH: "+path + " FN_CT: "+ str(fn_ct) +" COMMENTED_CT: "+str(commented_ct))            
    return docs

def create_index(args):
    client = Elasticsearch( "http://localhost:9200")
    client.indices.delete(index=args.index_name, ignore=[404])
    client.indices.create(index=args.index_name, settings = settings, mappings = mappings)


def load_data(index_name):
    
    #client = Elasticsearch( "http://localhost:9200/jobsearch")
    client = Elasticsearch( "http://localhost:9200/"+index_name)
    paths = []
    file_names = os.listdir("./dbs")
    print("file_names")
    print(file_names)
    for file_name in file_names:
        path = os.path.abspath("./dbs/"+file_name)
        print("abspath: "+path)
        paths.append(path)
    docs = load_annotated_db(paths)
    #docs = load_dataset(args.data)
    print("docs")
    print(docs)
    bulk(client, docs)


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Indexing elasticsearch documents.')
    parser.add_argument('--index_name', default='index.json', help='Elasticsearch index name.',required=True)

    settings = {
    "number_of_shards": 2,
    "number_of_replicas": 1
    }
    mappings = {
    "dynamic": "true",
    "_source": {
      "enabled": "true"
    },
    "properties": {
      "title": {
        "type": "text"
      },
      "text": { 
        "type": "text"
      },
      
    }
    }

    
    args = parser.parse_args()
    create_index(args)
    load_data(index_name)
