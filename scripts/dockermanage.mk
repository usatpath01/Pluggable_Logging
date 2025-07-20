cleanmanager:
	sudo lsof -i TCP:2377  
	sudo kill -9 $(sudo lsof -i TCP:2377) 2>/dev/null || true
	-docker rmi $(docker images -a -q) 2>/dev/null || true
	-docker rm $(docker ps -a -f status=exited -q) 2>/dev/null || true
	-docker stop $(docker ps -a -q) 2>/dev/null || true
	-docker rm $(docker ps -a -q) 2>/dev/null || true
	-docker network prune -f 2>/dev/null || true
	-docker system prune -a -f 2>/dev/null || true
	dpkg -l | grep -i docker
	sudo apt-get purge docker-ce docker-ce-cli containerd.io
	sudo rm -rf /var/lib/docker /etc/docker
	-sudo groupdel docker 2>/dev/null || true
	sudo rm -rf /usr/local/bin/docker-compose
	sudo rm -rf /etc/docker
	sudo rm -rf ~/.docker
	-sudo groupdel docker 2>/dev/null || true
	sudo apt-get autoremove

cleanworker:
	-docker rm $(docker ps -aq) 2>/dev/null || true
	-docker stop $(docker ps -a -q) 2>/dev/null || true
	-docker rm $(docker ps -a -q) 2>/dev/null || true
	-docker network prune -f 2>/dev/null || true
	-docker system prune -a -f 2>/dev/null || true
	sudo apt-get purge docker-ce docker-ce-cli containerd.io
	sudo rm -rf /var/lib/docker /etc/docker
	-sudo groupdel docker 2>/dev/null || true
	sudo rm -rf /usr/local/bin/docker-compose
	sudo rm -rf /etc/docker
	sudo rm -rf ~/.docker
	-sudo groupdel docker 2>/dev/null || true
	sudo apt-get autoremove

removedockermanager:
	sudo apt-get purge --auto-remove apparmor
	sudo service docker restart
	-docker system prune --all --volumes -f 2>/dev/null || true

install:
	sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
	-sudo rm -f /etc/apt/sources.list.d/docker.list
	-sudo rm -f /etc/apt/sources.list.d/archive_uri-https_download_docker_com_linux_ubuntu-*.list
	sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmour -o /etc/apt/trusted.gpg.d/docker.gpg
	echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
	sudo apt update
	sudo apt install docker-ce -y
	-sudo groupadd docker 2>/dev/null || true
	sudo usermod -aG docker ${USER}
	newgrp docker
	
	
	sudo curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)"  -o /usr/local/bin/docker-compose
	sudo mv /usr/local/bin/docker-compose /usr/bin/docker-compose
	sudo chmod +x /usr/bin/docker-compose

initmanager:
	sudo docker swarm init --advertise-addr <Manager-ip>

joinswarm:
	docker swarm join --token <Worker-Token> <Manager-ip>:2377

testswarm:
	 docker service create --name web-server --publish 8080:80 nginx:latest 
	 docker service scale web-server=4

installdockercompose:
	sudo curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)"  -o /usr/local/bin/docker-compose
	sudo mv /usr/local/bin/docker-compose /usr/bin/docker-compose
	sudo chmod +x /usr/bin/docker-compose