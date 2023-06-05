from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

function = input("Enter the function name to search : ")


def dfs(function_name, readMaps_list):

    resp = client.search(index=index_name, pretty=True, source=["called_function_list", "readMaps"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]

    content = resp["called_function_list"]
    readMaps = resp['readMaps']
    readMaps_list += readMaps
    for func in content:
        dfs(func, readMaps_list)

READMAPS = []
dfs(function, READMAPS)
print(f"Maps read throughout the FCG of function {function}")
print(READMAPS)