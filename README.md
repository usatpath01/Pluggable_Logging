# XLP_Distributed
The XLP_Distributed as 2 components: `XLP_COLLECTOR` and `XLP_GENERATOR`

```
Pluggable_Logging
├── XLP
└── XLP_COLLECTOR
```
## Configurations:
Configure the `serverIP` and `serverPort` in Pluggable_Logging/XLP/src/xlp.c
```
const char *serverIP = "10.5.20.X";
const int serverPort = XXXX;
```

1. To Build the image: 
`sudo docker-compose build`
2. Run the XLP_COLLECTOR in a Host:
Clone the repo
```
git clone https://github.com/usatpath01/Pluggable_Logging.git
```
In `docker-compose.yml` for the collector,  there will be a volume mapping, change it to the directory where you want the logs to come 
``` volumes:
      - /home/utkalika-ibm/XLP_Distributed/collector_logs:/app/logs
```
will be changed to 
```
volumes:
      - <your logs directory>:/app/logs
```
Then build it 
```
sudo docker-compose build
docker compose up collector_server -d
```
3. Once the collector server is up, run the XLP_GENERATOR in each other hosts where the microservice application containers run.
```
git clone https://github.com/usatpath01/Pluggable_Logging.git
sudo docker-compose build
docker compose up xlp -d
```
    
### To Test the logging framework with Application:
```
git clone https://github.com/usatpath01/DeathStarBench_XLP.git
sudo docker stack deploy --compose-file=docker-compose-swarm.yml dsb
```
