from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

repo = input("Enter the repository name : ")

resp = client.search(index=index_name, pretty=True, source=["readMaps", "updateMaps"], size=1000, query={
            "fuzzy": {
                "File": repo
            }
        })

hits = resp.raw['hits']['hits']

maps = []
for dic in hits:
    maps += dic["_source"]["readMaps"]
    maps += dic["_source"]["updateMaps"]

maps = set(maps)
print(f"List of Maps - {maps}")
counts = len(maps)
print(f"Number of Maps - {counts}")
