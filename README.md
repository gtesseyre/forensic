# Forensic
Development project about Contrail forensic analysis
Use Information from Contrail Analytics

### How to use it 
Assumint you are running it from a node that has Contrail VNC API installed 
```
apt-get install git

git clone https://github.com/gtesseyre/forensic.git

cd forensic/

root@5b3s25:~/forensic# python check_contrail.py --help
usage: check_contrail.py [-h] [-a OS_AUTH_URL] [-t OS_PROJECT_NAME]
                         [-u OS_USERNAME] [-p OS_PASSWORD] [-c CONTRAIL_API]
                         [-C CONTRAIL_ANALYTICS_API]

optional arguments:
  -h, --help            show this help message and exit
  -a OS_AUTH_URL, --os-auth-url OS_AUTH_URL
                        Openstack Authentication URL
  -t OS_PROJECT_NAME, --os-project-name OS_PROJECT_NAME
                        Openstack Project/Tenant Name
  -u OS_USERNAME, --os-username OS_USERNAME
                        Openstack Username
  -p OS_PASSWORD, --os-password OS_PASSWORD
                        Openstack Password
  -c CONTRAIL_API, --contrail-api CONTRAIL_API
                        Contrail API URL
  -C CONTRAIL_ANALYTICS_API, --contrail-analytics-api CONTRAIL_ANALYTICS_API
                        Contrail Analytics API URL
```

Create a file with all credentials and source it 
```
cat <<EOF> credentials
export OS_AUTH_URL=http://10.87.64.26:5000/v2.0/
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=contrail123
export CONTRAIL_API=http://10.87.64.26:8082
export CONTRAIL_ANALYTICS_API=http://10.87.64.26:8081
EOF

source credentials 
python check_contrail.py
```
Or use directly the python script passing environment variables as arguments
```
python check_contrail.py -a http://10.87.64.26:5000/v2.0/ -t admin -u admin -p contrail123 -c http://10.87.64.26:8082 -C http://10.87.64.26:8081
