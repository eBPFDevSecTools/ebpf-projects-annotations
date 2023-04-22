from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

helper = input("Enter the helper function name : ")

resp = client.search(index=index_name, pretty=True, source=["File", "funcName"], size=1000, query={
            "match": {
                "helper": helper
            }
        })

hits = resp.raw['hits']['hits']

ls = []
filenames = []
for dic in hits:
    ls.append(dic["_source"]["funcName"])
    filenames.append(dic["_source"]["File"])

ls = set(ls)
filenames = set(filenames)
print(f"List of Functions - {ls}")
print(f"File names of functions - {filenames}")
counts = len(ls)
print(f"Number of Functions - {counts}")
