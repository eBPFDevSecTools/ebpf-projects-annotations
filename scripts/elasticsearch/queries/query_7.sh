#!/bin/sh

let a "startLine";
let b "35";

echo $a
echo $b

curl -X GET -H 'Content-Type: application/json' 'http://localhost:9200/tmp2/_search?pretty' -d '{"query": {"match": {"'$a'" : '$b'}},"_source": ["funcName", "'$a'"]}' > ../responses/response_7.txt
