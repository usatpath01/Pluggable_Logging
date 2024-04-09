# XLP_Distributed
The XLP_Distributed as 2 components: `XLP_COLLECTOR` and `XLP_GENERATOR`

```
Pluggable_Logging
├── XLP
└── XLP_Distributed

## Configurations:
Configure the `serverIP` and `serverPort` in Pluggable_Logging/XLP/src/xlp.c
```
const char *serverIP = "10.5.20.X";
const int serverPort = XXXX;
```

1. To Build the image: 
`sudo docker-compose build`
2. Run the XLP_COLLECTOR in a Host:
```
docker compose up collector_server -d
```
3. Once the collector server is up, run the XLP_GENERATOR in each other hosts where the microservice application containers run.
```
docker compose up xlp -d
```
    
### To Test the logging framework with Application:
```
git clone https://github.com/usatpath01/DeathStarBench_XLP.git
sudo docker stack deploy --compose-file=docker-compose-swarm.yml dsb



    
    
 

