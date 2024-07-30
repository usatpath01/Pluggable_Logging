# Multihost Montioring Using Prometheus-CAdvisor-Grafana-NodeExporter
## Run CAdvisor and NodeExporter in swarm mode
```
docker stack deploy -c Pluggable_Logging/scripts/metrics_collector/docker-stack-cadvisor-nodeexporter.yml cadvisor_nodeexporter
```
## Run Prometheus and Grafana
```
cd Pluggable_Logging/scripts/metrics_collector/
docker-compose -f docker-compose-prometheus-grafana.yml up -d
docker-compose -f docker-compose-prometheus-grafana.yml down
```

## Dashboards Endpoints 
```
CAdvisor: http://<IP>>:9091
Prometheus: http://<IP>>:9092
Grafana: http://<IP>>:3000
```
In grafana dasboard, Go to 'Datasource'. Add your datasource as 'prometheus'. Once Datasource is added, go to 'Dashboard' and import the dashboard. (You can create your own dashboard)

## Grafana Import Dasboard 
```
Docker Swarm & Container Overview: 609
Node Exporter Full Dashboard: 1860
cAdvisor Dashboard:  14282
cAdvisor Docker Insights : 19908
```

# DeathStarBench: 
```
cd DeathStarBench_XLP/socialNetwork/
sudo docker stack deploy --compose-file=docker-compose-swarm.yml dsb
```

# Pluggable_Logging:
To up the XPLOG Collector on the Manager node:
```
cd Pluggable_Logging/
docker compose -f docker-compose-collector.yml up XPLOG_COLLECTOR -d
```
To up the XLP Agent on the worker node. Run the following script on the masternode. Confiure the script to add all the worker node IPs.
```
cd metrics_collector/docker-monitor/multihost
./run_xlp_up.sh
```

To down the service 
```
cd metrics_collector/docker-monitor/multihost
./run_xlp_down.sh
```
```
cd Pluggable_Logging/
docker compose -f docker-compose.yml down
```