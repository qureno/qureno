#!/bin/bash
if free | awk '/^Swap:/ {exit !$2}'; then
echo "Have swap"
else
sudo touch /var/swap.img
sudo chmod 600 /var/swap.img
sudo dd if=/dev/zero of=/var/swap.img bs=1024k count=2000
mkswap /var/swap.img
sudo swapon /var/swap.img
sudo echo "/var/swap.img none swap sw 0 0" >> /etc/fstab
fi
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get install mc htop git python-virtualenv ntpdate -y
sudo ntpdate -u pool.ntp.org
sudo mkdir /opt/qureno-core
cd /opt/qureno-core
wget https://github.com/qureno/qureno/releases/download/0.13.1.1/qureno-0.13.1.1-linux.tar.gz
tar -xvf qureno-0.13.1.1-linux.tar.gz
rm qureno-0.13.1.1-linux.tar.gz
mv qureno-0.13.1.1-linux/qurenod ./qurenod
mv qureno-0.13.1.1-linux/qureno-cli ./qureno-cli
mv qureno-0.13.1.1-linux/qureno-tx ./qureno-tx
mv qureno-0.13.1.1-linux/qureno-qt ./qureno-qt
rm -rf qureno-0.13.1.1-linux
chmod -R 755 /opt/qureno-core
cd /opt
git clone https://github.com/qureno/qureno-sentinel qureno-sentinel
cd qureno-sentinel
virtualenv ./venv
./venv/bin/pip install -r requirements.txt
cat <(crontab -l) <(echo "* * * * * cd /opt/qureno-sentinel && ./venv/bin/python bin/sentinel.py >/dev/null 2>&1") | crontab -
cd /opt/qureno-core
./qurenod -daemon
sleep 10
masternodekey=$(./qureno-cli masternode genkey)
./qureno-cli stop
sleep 3
echo -e "\nserver=1\nlisten=1\ndaemon=1\nmaxconnections=256\nmasternode=1\nmasternodeprivkey=$masternodekey\nrpcuser=RPCUSER\nrpcpassword=RPCPASSWORD\nrpcport=9798\nrpcallowip=127.0.0.1\n" >> "/root/.qureno/qureno.conf"
sleep 3
sudo sed -i -e "s/exit 0/sudo \-u root \/opt\/qureno-core\/qurenod \> \/dev\/null \&\nexit 0/g" /etc/rc.local
./qurenod -daemon
echo "Masternode private key: $masternodekey"
echo "Job completed successfully"
