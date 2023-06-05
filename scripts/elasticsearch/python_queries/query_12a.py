from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

function = input("Enter the function name to search : ")


def dfs(function_name):

    resp = client.search(index=index_name, pretty=True, source=["called_function_list", "compatibleHookpoints"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]

    content = resp["called_function_list"]
    compat = set(resp["compatibleHookpoints"])

    for func in content:
        compat = compat.intersection(dfs(func))
    
    return compat



hookpoints = dfs(function)
print(f"Compatible hookpoints throughout the FCG of function {function} : {hookpoints}")