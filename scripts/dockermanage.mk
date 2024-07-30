cleanmanager:
	sudo lsof -i TCP:2377  
	sudo kill -9 $(sudo lsof -i TCP:2377)
	docker rmi $(docker images -a -q)
	docker rm $(docker ps -a -f status=exited -q)
	docker stop $(docker ps -a -q)
	docker rm $(docker ps -a -q)
	docker network prune
	docker system prune -a
	dpkg -l | grep -i docker
	sudo apt-get purge docker-ce docker-ce-cli containerd.io
	sudo rm -rf /var/lib/docker /etc/docker
	sudo groupdel docker
	sudo rm -rf /usr/local/bin/docker-compose
	sudo rm -rf /etc/docker
	sudo rm -rf ~/.docker
	sudo groupdel docker
	sudo apt-get autoremove

cleanworker:
	docker rm $(docker ps -aq)
	docker stop $(docker ps -a -q)
	docker rm $(docker ps -a -q)
	docker network prune
	docker system prune -a
	sudo apt-get purge docker-ce docker-ce-cli containerd.io
	sudo rm -rf /var/lib/docker /etc/docker
	sudo groupdel docker
	sudo rm -rf /usr/local/bin/docker-compose
	sudo rm -rf /etc/docker
	sudo rm -rf ~/.docker
	sudo groupdel docker
	sudo apt-get autoremove

removedockermanager:
	sudo apt-get purge --auto-remove apparmor
	sudo service docker restart
	docker system prune --all --volumes

install:
	sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
	sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmour -o /etc/apt/trusted.gpg.d/docker.gpg
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
	sudo apt update
	sudo apt install docker-ce -y
	sudo groupadd docker
	sudo usermod -aG docker ${USER}
	newgrp docker
	sudo systemctl enable docker
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