from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

repo = input("Enter the repository name : ")
map = input("Enter the map name to search : ")


resp = client.search(index=index_name, pretty=True, source=["funcName"], size=1000, query={
            "bool": {
                "filter": {
                    "match_phrase": {
                    "File": repo
                    }
                },
                "must": {
                    "match_phrase": {
                    "updateMaps": map
                    }
                }
            }
        })

hits = resp.raw['hits']['hits']

funcs = set()
for dic in hits:
    funcs.add(dic["_source"]["funcName"])

print(f"List of Functions - {funcs}")
counts = len(funcs)
print(f"Number of Functions - {counts}")