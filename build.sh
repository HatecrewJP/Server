gcc -ggdb main.c -o Server
sudo setcap cap_net_raw+ep Server
