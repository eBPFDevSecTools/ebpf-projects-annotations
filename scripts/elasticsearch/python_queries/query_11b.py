from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

function = input("Enter the function name to search : ")


def dfs(function_name, readMaps, func_names, prev=None):

    resp = client.search(index=index_name, pretty=True, source=["called_function_list", "readMaps", "updateMaps"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]

    content = resp["called_function_list"]
    updateMaps = resp["updateMaps"]

    if set(readMaps).intersection(set(updateMaps)):
        func_names.append({"parent": prev, "successor": function_name})

    readMaps = resp["readMaps"]

    for func in content:
        dfs(func, readMaps, func_names, prev=function_name)
    

function_names = []
dfs(function, [], function_names)
print("Pairs of Functions which obey consumer-producer relation")
print(function_names)