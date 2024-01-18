# repositorio
#USUARIOS

#Creación de usuario:
#$ adduser nombre-usuario 


#FICHEROS

#Creación de un fichero:
#$ touch nombre-fichero

#Cambiar usuario asignado al fichero:
#$ chown nombre-usuario nombre-fichero

#Cambiar grupo asignado al fichero:
#$ chgrp nombre-grupo nombre-fichero

#Cambiar permisos de un fichero:
#$ chmod 777 nombre-fichero

#Copiar fichero de un dispositivo a otro:
#$ scp -i usuario-ubuntu.pem ubuntu@IP_Flotante:/ruta-fichero
#Importante: comprobar permisos de los ficheros y directorios si el comando falla 


#VOLÚMENES Y RAID

#Mostrar listado de dispositivos y volúmenes:
#$ lsblk

#Mostrar listado y espacio de dispositivos y volúmenes montados:
#$ df -h

#Crear partición en el disco:
#$ fdisk /dev/vdb (n/p/ / /+1G)

#Crear partición en el disco para montar un raid:
#$ fdisk /dev/vdb (n/p/ / /+1G/t/fd)

#Dar formato a una partición:
#$ sudo mkfs -t ext4 /dev/vdbX

#Montar un volumen/partición:
#$ sudo mount /dev/vdb1 /mnt

#Instalar librearías necesarias para utilizar raid:
#$ sudo apt install mdam 
#$ sudo modprobe linear multipath raid10

#Crear un nodo de archivos:
#$ sudo mknod /dev/md0 b 9 0

#Crear raid:
#$ sudo mdadm --create /dev/md0 --level=raid10 --raid-devices=4 /dev/dvb1 /dev/dvb2 /dev/dvb3 /dev/dvb4

#Mostrar estado de un raid creado:
#$ cat /proc/mdstat

#Dar formato a un raid:
#$ sudo mkfs.ext4 /dev/md0

#Montar raid sobre un directorio:
#$ sudo mount /dev/md0 /mnt

#Mostrar UUID de un volumen/raid:
#$ blkid /dev/md0

#Montar volumen/raid de manera persistente:
#$ nano /etc/fstab
#	 Utilizar el siguiente formato:
#	       UUID=109d5dbf-a0f2-4f91-81fd-3608e7c8c5a7 /mnt ext4 defaults 0 0

 
#SSH

#Fichero de configuración de SSH: 
#/etc/ssh/sshd_config

#Conexión SSH con contraseña: (PasswordAuthentication yes)
#$ nano /etc/ssh/sshd_config
#$ ssh ubuntu@IP_Flotante

#Generar las claves asimétricas del usuario: 
#$ ssh-keygen -m PEM -t rsa

#Conexión SSH con claves asimétricas: (PasswordAuthentication no)
#$ nano /etc/ssh/sshd_config
#$ ssh -i ubuntu-acq911.pem ubuntu@IP_Flotante

#Reiniciar el servicio SSH:
#$ /etc/init.d/ssh restart

 
#HTTP

#Fichero de configuración de HTTP: 
#/etc/apache2/sites-available/000-default.conf

#Ruta por defecto del servidor Apache: 
#/var/www/html/

#Instalar servidor web Apache:
#$ sudo apt update
#$ sudo apt upgrade
#$ sudo apt install apache2

#Instalar servidor web LAMP (Linux, Apache, MySQL, PHP):
#$ sudo apt update
#$ sudo apt upgrade
#$ sudo apt install apache2 php libapache2-mod-php
#$ sudo apt install default-mysql-server php-mysql php-pear

#Comprobar el estado de funcionamiento de Apache:
#$ sudo systemctl status apache2

#Cambiar directorio base de Apache:
#$ nano /etc/apache2/sites-available/000-default.conf
#	 Modificar la ruta al directorio deseado
#        Añadir las líneas:	<Directory /directorio-deseado>
#				Require all granted
#				</Directory>

#Modificar el contenido del index de Apache:
#$ echo “Página web diseñada por acq911” > /var/www/html/index.html

#Sustituir el fichero de configuración:
#$ sudo a2dissite 000-default && sudo a2ensite nuevo-fichero

#Configurar SSL en Apache:
#$ sudo a2ensite default-ssl
#$ sudo a2enmod ssl

#Reiniciar el servicio HTTP:
#$ sudo systemctl reload apache2


#GOOGLE CLOUD CONSOLE

#Establecer la zona horaria:
#$ gcloud config set compute/zone europe-west1-b

#Encender una instancia: 
#$ gcloud compute instances start nombre-instancia --zone europe-west1-b

#Apagar una instancia: 
#$ gcloud compute instances stop nombre-instancia --zone europe-west1-b

#Mostrar listado de instancias: 
#$ gcloud compute instances list

#Acceder a una instancia a través de SSH:
#$ gcloud compute ssh nombre-instancia

#Crear un volumen: 
#$ gcloud compute disks create nombre-volumen --size 20 --type pd-standard

#Asociar un volumen con una instancia: 
#$ gcloud compute instances attach-disk nombre-instancia --disk nombre-volumen

#Redimensionar un volumen: 
#$ gcloud compute disks resize nombre-volumen --size 40

#Crear un disco persistente a través de un script: 
#$ kubectl apply -f pvol-claim.yaml

 
#GOOGLE CLOUD DOCKER Y CLUSTERS

#Lista de repositorios creados en Artifact Registry:
#$ gcloud artifacts repositories list
 
#Lista de credenciales de la cuenta de Google Cloud:
#$ gcloud auth list
 
#Lista de proyectos creados de Google Cloud:
#$ gcloud config list project

#Establecer la zona horaria sobre la que vamos a trabajar:
#$ gcloud config set compute/zone europe-west1

#Establecer la zona horaria en docker:
#$ gcloud auth configure-docker europe-west1-docker.pkg.dev

#Descargar una imagen docker de un contenedor:
#$ docker pull us-docker.pkg.dev/google-samples/containers/gke/hello-app:1.0
 
#Etiquetar una imagen para su posterior subida:
#$ docker tag us-docker.pkg.dev/google-samples/containers/gke/hello-app:1.0 europe-west1-docker.pkg.dev/acq911-400915/biblioteca/ejemplo-acq911:acq911

#Subir una imagen docker a Artifact Registry:
#$ docker push europe-west1-docker.pkg.dev/acq911-400915/biblioteca/ejemplo-acq911:acq911
 
#Lista de imágenes almacenadas en el sistema:
#$ docker images
 
#Ejecutar un contenedor a partir de una imagen:
#$ docker run -d -p 82:80 nginx
 
#Lista de contenedores ejecutados disponibles:
#$ docker ps -a

#Acceder a un contenedor
#$ docker exec -it ID_Contenedor bash

#Generar una imagen de un contenedor personalizado con Dockerfile:
#$ docker build -t nginx-acq911 .
 
#Crear un nuevo cluster:
#$  gcloud container clusters create acq911-cluster-GKEStandard
 
#Acceder a un cluster:
#$ gcloud container clusters get-credentials acq911-cluster-GKEStandard
 
#Comprobar la versión de Kubernetes;
#$ kubectl version
 
#Comprobar la información de un cluster:
#$ kubectl cluster-info
 
#Crear un despliegue de un contenedor:
#$ kubectl create deployment nginx --image nginx:1.12.0
 
#Lista de pods de instancias disponibles:
#$ kubectl get pods
 
#Exponer un servicio a partir de un despliegue:
#$ kubectl expose deployment nginx --port 80 --type LoadBalancer
 
#Lista de servicios desplegados:
#$ kubectl get services
 
#Escalar el número de réplicas de pods:
#$ kubectl scale deployment nginx --replicas 10
 
#Eliminar un despliegue realizado:
#$ kubectl delete deployment nginx
 
#Eliminar un servicio desplegado:
#$ kubectl delete service nginx 


#SCRIPTS

#Script de contraseña para SSH (conexión-ssh.txt): 
##!/bin/sh
#/bin/echo "Actualizar repositorios"
#/usr/bin/apt -y update
#/bin/echo "Cambiar password"
#/bin/echo 'ubuntu:ubuntu' | chpasswd
#/bin/echo "Modificar sshd_config"
#/bin/sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
#/bin/systemctl restart ssh

#Script para Dockerfile (/dockerfile/Dockerfile): 
#FROM nginx
#COPY index.html /usr/share/nginx/html/index.html

#Script de copia de seguridad (copia-seguridad.sh): 
##!/bin/bash
#fecha=$(date +%d'_'%m'_'%Y)
#directorioDestino1='/mnt/volumen1'
#directorioDestino2='/mnt/volumen2'
#espacioDisponibleHome=$(du -bs $HOME | awk '{print OFS, $1}')
#espacioDisponibleD1=$(df -P $directorioDestino1 | grep -v -i Available | awk '{print $4}')
#espacioDisponibleD2=$(df -P $directorioDestino2 | grep -v -i Available | awk '{print $4}')
#copiaAntigua1="ls -t $directorioDestino1 | tail -n1"
#copiaAntigua2="ls -t $directorioDestino2 | tail -n1"
#while [$espacioDisponibleHome -gt $espacioDisponibleD1 && $espacioDisponibleHome -gt $espacioDisponibleD2];
#do
#rm -f "$copiaAntigua1"
#rm -f "$copiaAntigua2"
#espacioDisponibleD1=$(df -P $directorioDestino1 | grep -v -i Available | awk '{print $4}')
#espacioDisponibleD2=$(df -P $directorioDestino2 | grep -v -i Available | awk '{print $4}')
#echo "Copias antiguas borradas"
#copiaAntigua1="ls -t $directorioDestino1 | tail -n1"
#copiaAntigua2="ls -t $directorioDestino2 | tail -n1"
#done
#tar -cvzpf $directorioDestino1/copia-acq911-$fecha.tar.gz $HOME
#tar -cvzpf $directorioDestino2/copia-acq911-$fecha.tar.gz $HOME
#echo "Copia finalizada"

#Crear un disco persistente (pvol-claim.yaml) : 
#apiVersion: v1
#kind: PersistentVolumeClaim
#metadata:
#  name: nginx-disk
#spec:
#  accessModes:
#    - ReadWriteOnce
#  resources:
#    requests:
#      storage: 30Gi

#Crear servicios LDAP (osixia-acq911.yaml): 
#apiVersion: v1
#kind: Secret
#metadata:
# name: openldap-secrets
# namespace: default
#type: Opaque
#data:
# organizatation: "Q2xvdWRBZG1pbnMNCg==" #myorganization
# domain: "cHJ1ZWJhLm9yZw0K" #mydomain
# password: "QWRtaW4=" #mypassword
#---
#apiVersion: apps/v1
#kind: Deployment
#metadata:
# name: openldap-acq911
# namespace: default
# labels:
# app: openldap
#spec:
# replicas: 1
# selector:
# matchLabels:
# app: openldap
# template:
# metadata:
# labels:
# app: openldap
# spec:
# containers:
# - name: openldap
# image: osixia/openldap:1.3.0
# ports:
# - containerPort: 389
# - containerPort: 636
# env:
# - name: LDAP_ORGANISATION
# valueFrom:
# secretKeyRef:
# name: openldap-secrets
# key: organizatation
# - name: LDAP_DOMAIN
# valueFrom:
# secretKeyRef:
# name: openldap-secrets
# key: domain
# - name: LDAP_ADMIN_PASSWORD
# valueFrom:
# secretKeyRef:
# name: openldap-secrets
# key: password
#---
#apiVersion: v1
#kind: Service
#metadata:
# name: openldap-acq911-service
# namespace: default
#spec:
# selector:
# app: openldap
# ports:
# - name: openldap1
# protocol: TCP
# port: 389
# targetPort: 389
# - name: openldap2
# protocol: TCP
# port: 636
# targetPort: 636
#---
#apiVersion: apps/v1
#kind: Deployment
#metadata:
# name: phpldapadmin-acq911
# namespace: default
# labels:
# app: phpldapadmin
#spec:
# replicas: 1
# selector:
# matchLabels:
# app: phpldapadmin
# template:
# metadata:
# labels:
# app: phpldapadmin
# spec:
# containers:
# - name: phpldapadmin
# image: osixia/phpldapadmin:0.9.0
# ports:
# - containerPort: 443
# env:
# - name: PHPLDAPADMIN_LDAP_HOSTS
# value: openldap-acq911-service
#---
#apiVersion: v1
#kind: Service
#metadata:
# name: phpldapadmin-acq911-service
# namespace: default
#spec:
# type: LoadBalancer
# selector:
# app: phpldapadmin
# ports:
# - protocol: TCP
# port: 8443
# targetPort: 443

 
#INFORMACIÓN IMPORTANTE

#DNS de configuración de redes:
#150.214.156.2
#8.8.8.8

#Número de dispositivos necesarios para cada raid:
#RAID0: 2 dispositivos		RAID4: 3 dispositivos		RAID6: 4 dispositivos
#RAID1: 2 dispositivos		RAID5: 3 dispositivos		RAID10: 4 dispositivos

#Ruta por defecto de los ficheros NGINX:
#/usr/share/nginx

#Puertos abiertos en cada uno de los servicios:
#HTTP: 22, 80 y 3389		NGINX: 80		SSH: 22		GHOST: 2368
#VISUALIZER: 8080		VOTE: 80		RESULT: 80	WORKER: 8080	

 
#POSIBLES EJERCICIOS

#Implementar un servicio de correo electrónico en un cluster:
#$ docker run --name=axigen -dt -v pvc-605cb69d-6904-471e-9c17-2da880fe9bce:/axigen/var -p 443:443 -p 9443:9443 -p 993:993 -p 995:995 -p 25:25 -p 465:465 -p 9000:9000 -p 7000:7000 axigen/axigen
#$ docker images
#$ docker tag axigen/axigen:latest axigen-acq911:acq911
#$ docker images
#$ docker ps -a
#$ docker exec -it c7527289eb44 bash
## telnet localhost 9000
#^]
#[ Acceder desde el terminal a la “Vista previa en el puerto 9000” y crear una cuenta ]
#[ Skip this step, Continue ]
#[ Crear un dominio y asignar la contraseña, Finish ]
#$ docker ps -a
#$ sudo docker commit c7527289eb44 mailserver-acq911
#$ docker images
#$ docker tag mailserver-acq911:latest europe-west1-docker.pkg.dev/acq911-400915/biblioteca/mailserver-acq911:acq911
#$ docker push europe-west1-docker.pkg.dev/acq911-400915/biblioteca/mailserver-acq911:acq911
#[ Crear el cluster Autopilot ]
#[ Crear carga de trabajo de la imagen mailserver-acq911 y el cluster Autopilot ]
#[ Al crear la carga, exponer el servicio con balanceador de cargas y añadiendo los puertos 9000:9000, 443:443 y 25:25 ]
#$ gcloud container clusters get-credentials acq911-cluster-gkeautopilot
#$ telnet IP_Balanceador_Cargas 25
#HELO
#MAIL FROM: Pepe@usuario
#RCPT TO: Ana@usuario
#DATA
#Date: Thur, 18 Jan 18:00:00
#From: Pepe@usuario
#To: Ana@usuario
#Subject: Hola
#
#Hola Ana, soy Pepe
#.
#QUIT

#Implementar un servicio blog:
#$ docker pull ghost
#$ docker images
#$ docker tag ghost:latest europe-west1-docker.pkg.dev/acq911-400915/biblioteca/blogserver-acq911:acq911
#$ docker images
#$ gcloud auth configure-docker europe-west1-docker.pkg.dev
#$ docker push europe-west1-docker.pkg.dev/acq911-400915/biblioteca/blogserver-acq911:acq911
#[ Accedemos a Artifact Registry e implementamos la imagen en Cloud Run habilitando el puerto 2368 ]

#Implementar un servicio LDAP:
#$ docker pull osixia/openldap
#$ docker run --env LDAP_ORGANISATION="CloudAdmins" --env LDAP_DOMAIN="prueba.org" --env LDAP_ADMIN_PASSWORD="Admin" --detach osixia/openldap
#$ docker pull osixia/phpldapadmin
#$ docker tag osixia/phpldapadmin europe-west1-docker.pkg.dev/acq911-400915/biblioteca/osixia/phpldapadmin:acq911
#$ docker images
#$ docker push europe-west1-docker.pkg.dev/acq911-400915/biblioteca/osixia/phpldapadmin:acq911
#$ curl -s checkip.dyndns.org | sed -e ‘s/.Current IP Address: //’ -e ‘s/<.$//’
#$ docker run -p 8443:443 -e PHPLDAPADMIN_LDAP_HOSTS=IP_Balanceador -d osixia/phpldapadmin
#$ docker ps -a
#$ docker commit -c ‘CMD [“/container/tool/run”, “--foreground”]’ 7af646661c43 openldap-acq911
#$ docker commit -c ‘CMD [“/container/tool/run”, “--foreground”]’ 288fe69828fd phpldapadmin-acq911
#$ docker images
#$ docker tag openldap-acq911:latest europe-west1-docker.pkg.dev/acq911-400915/biblioteca/openldap-acq911:acq911
#$ docker tag phpldapadmin-acq911:latest europe-west1-docker.pkg.dev/acq911-400915/biblioteca/phpldapadmin-acq911:acq911
#$ docker push europe-west1-docker.pkg.dev/acq911-400915/biblioteca/openldap-acq911:acq911
#$ docker push europe-west1-docker.pkg.dev/acq911-400915/biblioteca/phpldapadmin-acq911:acq911
#[ Si no funciona: Consultar el script “Creación de servicios LDAP”
#   Copiar el script y ejecutarlo usando $ kubectl create -f osixia-acq911.yaml ]

#Instalar servidor web LAMP (Linux, Apache, MySQL, PHP):
#$ sudo apt update
#$ sudo apt upgrade
#$ sudo apt install apache2 php libapache2-mod-php
#$ sudo apt install default-mysql-server php-mysql php-pear

#Utilizar una MV Mikrotik entre una red de proyecto y una red privada:
#[ Crear el router ]
#[ Crear la red de proyecto (con puerta de enlace y DHCP activados) y conectar la interfaz al router ]
#[ Crear la red privada (con puerta de enlace y DHCP desactivados) ]
#[ Crear grupos de seguridad de HTTP/HTTPS y SSH+ICMP ]
#[ Crear la MV Mikrotik (con sabor tiny y grupos de seguridad HTTP y SSH+ICMP) y conectar ambas redes mediante interfaces ]
#[ Asignar IP flotante a la MV Mikrotik y acceder via HTTP ]
#[ Modificar el MTU de todas las interfaces a 1450 ]
#[ Añadir configuración de la red privada:
#- IP Addresses --> Address: IP de la interfaz que conecta la MV Mikrotik con la red privada/24; Network --> Dirección de la red privada; Interface --> ether2 
#- IP Firewall --> NAT -->  Añadir --> Chain: srcnat; Out. Interface: ether1; Action: masquerade ]
#[ Crear MVs si hace falta en la red de proyecto aunque alguna sea de la red privada ]
#[ Asignas IP flotante a cada una ]
#[ Actualizar cada máquina virtual:
#  $ sudo apt-get update
#  $ sudo apt-get upgrade ]
#[ Centrándonos en la MV que corresponde a la red privada:
#  $ sudo apt install ifupdown net-tools 
#  Ver ficheros /etc/network/interfaces, /etc/hosts, /etc/hostname, /etc/resolv.conf 
#  Editar el fichero /etc/systemd/system/network-online.targets.wants/networking.service estableciendo “TimeoutStartSec=30sec” 
#  Ver fichero /etc/netplan/50-cloud-init.yaml 
#  Crear/Modificar el fichero /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg estableciendo como único contenido “network: {config: disabled}” 
#  Instalar Apache:
#  $ sudo apt install apache2 
#  Apagar la MV que corresponde a la red privada, desconectarla de la red de proyecto y conectarla a la red privada
#  Establecer la configuración estática con el fichero /etc/netplan/50-cloud-init.yaml de la forma:
#  network:
#      version: 2
#      ethernets:
#          ens3:
#              dhcp4: no
#              addresses:
#                - IP_Estática_MV/24
#              gateway4: IP_Interfaz_Conectada_Entre_Red_Privada_Y_Mikrotik
#              nameservers:
#                  addresses:
#                    - 1.1.1.1
#                    - 8.8.8.8
#  Reiniciar la MV ]
#[ Centrándonos en nuestro propio dispositivo:
#  Descargar credenciales .sh de openstack y copiarlos a la MV a través de scp:
#  $ scp acq911-openrc.sh ubuntu@IP_flotante:/home/ubuntu ]
#[ Centrándonos en la MV que corresponde a la red de proyecto:
#  $ sudo apt install python3-openstackclient
#  $ chmod 777 acq911-openrc.sh
#  $ openstack --insecure port list
#  Identificamos los puertos correspondientes a las dos interfaces de la MV Mikrotik y a la interfaz que conecta la red privada a la MV anterior
#  $ openstack --insecure port set ID_puerto_1 –disable-port-security –no-security-group
#  $ openstack --insecure port show ID_puerto_1
#  $ openstack --insecure port set ID_puerto_2 –disable-port-security –no-security-group
#  $ openstack --insecure port show ID_puerto_2
#   $ openstack --insecure port set ID_puerto_3 –disable-port-security –no-security-group
#   $ openstack --insecure port show ID_puerto_3
#   $ ip route add IP_Red_Privada/24 via IP_Interfaz_Conectada_Entre_Red_Proyecto_Y_Mikrotik
#   $ sudo service systemd-networkd restart ]
#[ Accediendo a la MV Mikrotik a través de HTTP:
#  Añadir redireccionamiento de puertos:
#  - IP Firewall --> NAT --> Añadir --> Chain: dstnat; Protocol: 6 (tcp); Dst. Port: 3389; In. Interface: all ethernet; Action: dst-nat; To Addresses: IP_MV_Red_Privada; To Ports: 80 ]
#[ Si se quiere limitar el ancho de banda:
#  - IP Firewall --> Layer 7 --> Añadir --> Name: Youtube; Regexp: 142.250.200.110 | 142.250.185.14 | 142.250.184.14 | 142.250.184.174 | 216.58.215.142 | 142.250.178.174 |
#                                           142.250.200.78 | 142.250.201.78 | 142.250.200.142 | 216.58.215.174; Comment: Servidores de youtube limitados 
#  - IP Firewall --> Filter Rules --> Añadir --> Chain: forward; In. Interface: ether3; Layer7 Protocol: YOUTUBE; Action: add dst to a address list; Address List: YOUTUBE_address;
#                                                Timeout: none dynamic 
#  - IP Firewall --> Mangle --> Añadir --> Chain: forward; Protocol: 6 (tcp); Src. Address List: YOUTUBE_address; Action: mark connection; New Connection Mark: YOUTUBE_connection; 
#                                          Passthrough: √
#  - IP Firewall --> Mangle --> Añadir --> Chain: forward; Connection Mark: YOUTUBE_connection; Action: mark packet; New Packet Mark: YOUTUBE_packet, Passthrough: □ 
#  - Queues --> Queue Tree --> Añadir --> Name: YOUTUBE; Parent: ether3; Packet Marks: YOUTUBE_packet; Queue Type: default-small; Limit At: 500k; Max Limit: 500k
#  - IP Firewall --> Address Lists --> Añadir/Ver --> Name: YOUTUBE_address; Address: IP_MV_Red_Privada ]
#Crear MV en red de proyecto y acceso con claves SSH en Openstack:
#[ Crear el router ]
#[ Crear la red y subred habilitando la puerta de enlace y el DHCP ]
#[ Crear el grupo de seguridad de SSH ] 
#[ Crear la MV y asignar IP flotante] 
#[ Generar las claves asimétricas del usuario: $ ssh-keygen -m PEM -t rsa ] 
#[ Copiar la clave pública en authorized_keys y la privada a nuestro dispositivo ] 
#[ Desactivar el acceso con contraseña en el fichero /etc/ssh/sshd_config ] 
#[ Reiniciar el servicio: $ sudo /etc/init.d/ssh restart ]
#[ Acceder a la MV con SSH: $ ssh -i ubuntu-acq911.pem ubuntu@IP_Flotante ]

#Crear MV en red de proyecto y servidor HTTP en raid10:
#[ Crear el router ]
#[ Crear la red y subred habilitando la puerta de enlace y el DHCP ]
#[ Crear el grupo de seguridad de HTTP ]
#[ Crear la MV y asignar IP flotante ]
#[ Crear el volumen y asignarlo a la MV ]
#[ Particionar tanto como necesite el raid: $ fdisk /dev/vdb (n/p/ / /+1G/t/fd) ]
#[ Dar formato a cada partición: $ sudo mkfs -t ext4 /dev/vdbX ]
#[ Instalar mdadm y librerías: $ sudo apt install mdam
#                              $ sudo modprobe linear multipath raid10 ]
#[ Crear un nodo de archivos: $ sudo mknod /dev/md0 b 9 0 ]
#[ Crear el raid: $ sudo mdadm --create /dev/md0 --level=raid10 --raid devices=4 /dev/dvb1 /dev/dvb2 /dev/dvb3 /dev/dvb4 ]
#[ Mostrar el estado del raid: $ cat /proc/mdstat ]
#[ Dar formato al raid creado: $ sudo mkfs.ext4 /dev/md0 ]
#[ Montar el raid en el punto de montaje: $ sudo mount /dev/md0 /mnt ]
#[ Obtener el UUID del raid: $ blkid /dev/md0 ]
#[ Montar de manera persistente el raid en el fichero /etc/fstab:
#  UUID=109d5dbf-a0f2-4f91-81fd-3608e7c8c5a7 /mnt ext4 defaults 0 0 ]
#[ Reiniciar la MV para comprobar el funcionamiento: $ reboot ]
#[ Actualizar los paquetes y los repositorios: $ sudo apt update
#		           		       $ sudo apt upgrade ]
#[ Instalar apache: $ sudo apt install apache2 ]
#[ Comprobar el estado de apache: $ sudo systemctl status apache2 ]
#[ Realizar una copia del index y del fichero de configuración de apache ]
#[ Modificar el index del servidor web: $ echo “Página web diseñada por acq911” > /var/www/html/index.html ]
#[ Copiar el index al punto de montaje: $ cp /var/www/html/index.html /mnt ]
#[ Cambiar directorio base en /etc/apache2/sites-available/000-default.conf a /mnt y añadir: <Directory /mnt>
#									                     Require all granted
#									                     </Directory> ]
#[ Sustituir el fichero de configuración: $ sudo a2dissite 000-default && sudo a2ensite nuevo-sitio ]
#[ Reiniciar el servicio de apache: $ sudo systemctl reload apache2 ]

#Crear MV en redes distintas y con acceso SSH por contraseña en Google Cloud:
#[ Crear la red y subred de laboratorio seleccionando todas las redes firewall ]
#[ Crear la MV examen-acq911 y conectarla a la red default y a laboratorio ] 
#[ Crear la MV privada-acq911 y conectarla a la red laboratorio ]
#[ Crear el usuario gerente en ambas máquinas: $ adduser gerente ]
#[ Activar el acceso con contraseña en el fichero /etc/ssh/sshd_config ]
#[ Reiniciar el servicio: $ /etc/init.d/ssh restart ] 
#[ Acceder a examen-acq911 por SSH: $ ssh gerente@IP_Flotante ]
#[ Acceder desde examen-acq911 a privada-acq911: $ ssh gerente@IP_Flotante ]
