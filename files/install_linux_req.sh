curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py

sudo apt-get install python3 -y
sudo apt-get install python3-bs4 -y
sudo apt-get install nmap -y

# Centos installsudo
sudo yum install -y python3
sudo yum install -y nmap
# install dpkg on Centos
sudo yum -y install epel-release
sudo yum repolist
sudo yum install dpkg-devel dpkg-dev
sudo yum -y install dpkg

python3 -m pip install couchdb2
python3 -m pip install python-nmap
python3 -m pip install jsonlib-python3
python3 -m pip install pandas
python3 -m pip install wmi
python3 -m pip install psutil