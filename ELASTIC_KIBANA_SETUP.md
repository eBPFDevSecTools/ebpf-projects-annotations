## Steps for setting up Elastic 

1. Install Elasticsearch by following the steps given in this link:
[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-elasticsearch-on-ubuntu-22-04](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-elasticsearch-on-ubuntu-22-04)

2. Loading the JSON data into Elasticsearch index (refer to the README)
[https://github.com/eBPFDevSecTools/ebpf-projects-annotations/tree/master/src/elasticsearch](https://github.com/eBPFDevSecTools/ebpf-projects-annotations/tree/master/src/elasticsearch)
3. Run this sample request in the shell to test if the data has been loaded correctly into the index
	```GET http://localhost:9200/<index_name>```
	


## Steps for setting up Kibana

1. Install Kibana by following the steps given in this link:
https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elastic-stack-on-ubuntu-22-04

2.  Open the browser and run the following to visualise the dashboard:
```http://localhost:5601```

3. Sample query to test querying using Kibana
	```GET <index_name>```

4. To test more extensive queries using python client, refer to the following link:
[https://github.com/aashu2303/ebpf-projects-annotations/tree/master/scripts/elasticsearch](https://github.com/aashu2303/ebpf-projects-annotations/tree/master/scripts/elasticsearch)


	
