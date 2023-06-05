from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

field = input("Enter the field name : ")
value = input("Enter the field value to search : ")


resp = client.search(index=index_name, pretty=True, source=["funcName"], size=1000, query={
            "match": {
                field : value
            }
        })

hits = resp.raw['hits']['hits']

funcs = set()
for dic in hits:
    funcs.add(dic["_source"]["funcName"])

print(f"List of Functions - {funcs}")
counts = len(funcs)
print(f"Number of Functions - {counts}")