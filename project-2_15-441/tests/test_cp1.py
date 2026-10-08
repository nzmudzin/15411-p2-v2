#!/usr/bin/env python3
# Copyright (C) 2022 Carnegie Mellon University
#
# This file is part of the TCP in the Wild course project developed for the
# Computer Networks course (15-441/641) taught at Carnegie Mellon University.
#
# No part of the project may be copied and/or distributed without the express
# permission of the 15-441/641 course staff.

from pathlib import Path

from scapy.all import rdpcap
from fabric import Connection
from scapy.all import sniff, send, Raw
from scapy.layers.inet import IP, UDP
from common import CMUTCP, ACK_MASK, SYN_MASK, TIMEOUT, IFNAME, TESTING_HOST_IP, TESTING_HOST_PORT, ip, udp
from common import PCAP, CMUTCP, ACK_MASK, IP_ADDRS


def test_pcap_packets_max_size():
    """Basic test: Check packets are smaller than max size"""
    print("Running test_pcap_packets_max_size()")
    print(
        "Please note that it's now testing on a sample test.pcap file. "
        "You should generate your own pcap file and run this test."
    )
    packets = rdpcap(PCAP)
    if len(packets) <= 10:
        print("Test Failed")
        return
    for pkt in packets:
        if CMUTCP in pkt:
            if len(pkt[CMUTCP]) > 1400:
                print("Found packet with length greater than max size")
                print("Test Failed")
                return
    print("Test passed")


def test_pcap_acks():
    """Basic test: Check that every data packet sent has a corresponding ACK
    Ignore handshake packets.
    """
    print("Running test_pcap_acks()")
    print(
        "Please note that it's now testing on a sample test.pcap file. "
        "You should generate your own pcap file and run this test."
    )
    packets = rdpcap(PCAP)
    if len(packets) <= 10:
        print("Test Failed")
        return

    expected_acks = []
    ack_nums = []
    for pkt in packets:
        if CMUTCP in pkt:
            # Ignore handshake packets, should test in a different test.
            if pkt[CMUTCP].flags == 0:
                payload_len = pkt[CMUTCP].plen - pkt[CMUTCP].hlen
                expected_acks.append(pkt[CMUTCP].seq_num + payload_len)
            elif pkt[CMUTCP].flags == ACK_MASK:
                ack_nums.append(pkt[CMUTCP].ack_num)

    # Probably not the best way to do this test!
    if set(expected_acks) == set(ack_nums):
        print("Test Passed")
    else:
        print("Test Failed")


# This will try to run the server and client code.
def test_run_server_client():
    """Basic test: Run server and client, and initiate the file transfer."""
    print("Running test_run_server_client()")

    # We are using `tmux` to run the server and client in the background.
    #
    # This might also help you debug your code if the test fails. You may call
    # `getchar()` in your code to pause the program at any point and then use
    # `tmux attach -t pytest_server` or `tmux attach -t pytest_client` to
    # attach to the relevant TMUX session and see the output.

    start_server_cmd = (
        "tmux new -s pytest_server -d /vagrant/project-2_15-441/server"
    )
    start_client_cmd = (
        "tmux new -s pytest_client -d /vagrant/project-2_15-441/client"
    )
    stop_server_cmd = "tmux kill-session -t pytest_server"
    stop_client_cmd = "tmux kill-session -t pytest_client"

    failed = False

    original_file = Path("/vagrant/project-2_15-441/src/cmu_tcp.c")
    received_file = Path("/tmp/file.c")

    received_file.unlink(missing_ok=True)

    with (
        Connection(
            host=IP_ADDRS["server"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as server_conn,
        Connection(
            host=IP_ADDRS["client"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as client_conn,
    ):
        try:
            server_conn.run(start_server_cmd)
            server_conn.run("tmux has-session -t pytest_server")

            client_conn.run(start_client_cmd)
            client_conn.run("tmux has-session -t pytest_client")

            # Exit when server finished receiving file.
            server_conn.run(
                "while tmux has-session -t pytest_server; do sleep 1; done",
                hide=True,
            )
        except Exception:
            failed = True

        try:
            client_conn.run("tmux has-session -t pytest_client", hide=True)
            print("stop client")
            client_conn.run(stop_client_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if client already shut down.
            pass
        try:
            server_conn.local("tmux has-session -t pytest_server", hide=True)
            print("stop server")
            server_conn.local(stop_server_cmd, hide=True)
        except Exception:
            # Ignore error here that may occur if server already shut down.
            pass
        if failed:
            print("Test failed: Error running server or client")
            return

        # Compare SHA256 hashes of the files.
        server_hash_result = server_conn.run(f"sha256sum {received_file}")
        client_hash_result = client_conn.run(f"sha256sum {original_file}")

        if not server_hash_result.ok or not client_hash_result.ok:
            print("Test failed: Error getting file hashes")
            return

        server_hash = server_hash_result.stdout.split()[0]
        client_hash = client_hash_result.stdout.split()[0]

        if server_hash != client_hash:
            print("Test failed: File hashes do not match")
            return

        print("Test passed")


def test_basic_reliable_data_transfer():
    """Basic test: Check that when you run server and client starter code
    that the input file equals the output file
    """
    # Can you think of how you can test this? Give it a try!
    pass


def test_basic_retransmit():
    """Basic test: Check that when a packet is lost, it's retransmitted,
    and the transfer still completes correctly despite the loss."""
    print("Running test_basic_retransmit()")

    start_server_cmd = (
    "tmux new -s pytest_server -d "
    "'/vagrant/project-2_15-441/server > /tmp/server.log 2>&1'"
    )
    start_client_cmd = (
        "tmux new -s pytest_client -d "
        "'/vagrant/project-2_15-441/client > /tmp/client.log 2>&1'"
    )
    stop_server_cmd = "tmux kill-session -t pytest_server"
    stop_client_cmd = "tmux kill-session -t pytest_client"

    original_file = Path("/vagrant/project-2_15-441/src/cmu_tcp.c")
    received_file = Path("/tmp/file.c")

    received_file.unlink(missing_ok=True)

    with (
        Connection(
            host=IP_ADDRS["server"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as server_conn,
        Connection(
            host=IP_ADDRS["client"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as client_conn,
    ):
        failed = False
        try:
            # Add loss on the client (sender) side only, matching the
            # pattern from the CP2 experiment instructions.
            client_conn.run(
                "export IFNAME=$(ifconfig | grep -B1 10.0.1. | grep -o \"^\\w*\") && "
                "sudo tcset $IFNAME --rate 100Mbps --delay 20ms "
                "--loss 5% --overwrite",
                hide=True,
            )

            server_conn.run(start_server_cmd)
            server_conn.run("tmux has-session -t pytest_server")

            client_conn.run(start_client_cmd)
            client_conn.run("tmux has-session -t pytest_client")

            # Exit when server finished receiving file.
            server_conn.run(
                "while tmux has-session -t pytest_server; do sleep 1; done",
                hide=True,
            )
        except Exception as e:
            print(f"Exception: {e}")
            failed = True
        finally:
            # Always remove the loss config, even if something above failed.
            try:
                client_conn.run(
                    "export IFNAME=$(ifconfig | grep -B1 10.0.1. | grep -o \"^\\w*\") && "
                    "sudo tcdel $IFNAME --all",
                    hide=True,
                )
            except Exception:
                pass

        try:
            client_conn.run("tmux has-session -t pytest_client", hide=True)
            client_conn.run(stop_client_cmd, hide=True)
        except Exception:
            pass
        try:
            server_conn.run("tmux has-session -t pytest_server", hide=True)
            server_conn.run(stop_server_cmd, hide=True)
        except Exception:
            pass

        if failed:
            print("Test failed: Error running server or client")
            return

        server_hash_result = server_conn.run(f"sha256sum {received_file}")
        client_hash_result = client_conn.run(f"sha256sum {original_file}")

        if not server_hash_result.ok or not client_hash_result.ok:
            print("Test failed: Error getting file hashes")
            return

        server_hash = server_hash_result.stdout.split()[0]
        client_hash = client_hash_result.stdout.split()[0]

        if server_hash != client_hash:
            print("Test failed: File hashes do not match despite retransmission")
            return

        print("Test passed")

def test_initiator_single_data_packet():
    """Check that a freshly-handshaken initiator correctly acks a single
    data packet sent immediately after the handshake completes."""
    print("Running test_initiator_single_data_packet()")

    START_CLIENT_CMD = (
        "tmux new -s pytest_client_single -d "
        "/vagrant/project-2_15-441/client"
    )
    STOP_CLIENT_CMD = "tmux kill-session -t pytest_client_single"

    with Connection(
        host=TESTING_HOST_IP,
        user="vagrant",
        connect_kwargs={"password": "vagrant"},
    ) as conn:
        try:
            conn.run(START_CLIENT_CMD)
            conn.run("tmux has-session -t pytest_client_single")

            # Wait for the initiator's SYN.
            syn_candidates = sniff(
                iface=IFNAME,
                lfilter=lambda p: (
                    CMUTCP in p
                    and p[CMUTCP].flags == SYN_MASK
                    and IP in p
                    and p[IP].src == TESTING_HOST_IP
                ),
                count=1,
                timeout=TIMEOUT,
            )
            if not syn_candidates:
                print("Did not receive SYN from initiator.")
                print("Test Failed")
                return
            syn_pkt = syn_candidates[0]
            client_isn = syn_pkt[CMUTCP].seq_num
            client_port = syn_pkt[UDP].sport
            print(f"Captured client SYN: seq={client_isn}, port={client_port}")

            # Build our UDP layer using the client's REAL ephemeral port,
            # not the hardcoded TESTING_HOST_PORT from common.py.
            my_udp = UDP(sport=TESTING_HOST_PORT, dport=client_port)

            my_isn = 5000
            syn_ack_pkt = (
                ip /
                my_udp /
                CMUTCP(
                    plen=25,
                    seq_num=my_isn,
                    ack_num=client_isn + 1,
                    flags=SYN_MASK | ACK_MASK,
                    source_port=TESTING_HOST_PORT,
                    destination_port=client_port,
                )
            )
            send(syn_ack_pkt, iface=IFNAME)

            ack_candidates = sniff(
                iface=IFNAME,
                lfilter=lambda p: (
                    CMUTCP in p
                    and p[CMUTCP].flags == ACK_MASK
                    and IP in p
                    and p[IP].src == TESTING_HOST_IP
                ),
                count=1,
                timeout=TIMEOUT,
            )
            ack_pkt = ack_candidates[0] if ack_candidates else None

            if (
                ack_pkt is None
                or ack_pkt[CMUTCP].ack_num != my_isn + 1
            ):
                print("Did not receive valid final ACK from initiator.")
                if ack_pkt is not None:
                    print(
                        f"Got flags={ack_pkt[CMUTCP].flags}, "
                        f"ack_num={ack_pkt[CMUTCP].ack_num}, "
                        f"expected ack_num={my_isn + 1}"
                    )
                else:
                    print("ack_pkt is None (no response received)")
                print("Test Failed")
                return

            # Handshake done. Send exactly one data packet.
            payload = "x"
            data_pkt = (
                ip /
                my_udp /
                CMUTCP(
                    plen=25 + len(payload),
                    seq_num=my_isn + 1,
                    ack_num=client_isn + 1,
                    flags=ACK_MASK,
                    source_port=TESTING_HOST_PORT,
                    destination_port=client_port,
                )
                / Raw(load=payload)
            )
            send(data_pkt, iface=IFNAME)

            response_candidates = sniff(
                iface=IFNAME,
                lfilter=lambda p: (
                    CMUTCP in p
                    and p[CMUTCP].flags == ACK_MASK
                    and IP in p
                    and p[IP].src == TESTING_HOST_IP
                    and p[CMUTCP].ack_num != my_isn + 1
                ),
                count=1,
                timeout=TIMEOUT,
            )
            response = response_candidates[0] if response_candidates else None

            expected_ack = my_isn + 1 + len(payload)
            if response is None:
                print("No response to data packet.")
                print("Test Failed")
                return
            if response[CMUTCP].flags != ACK_MASK:
                print("ACK packet does not contain ACK flag")
                print("Test Failed")
                return
            if response[CMUTCP].ack_num != expected_ack:
                print(
                    f"ACK packet has incorrect ACK number. Expected "
                    f"{expected_ack}. Got {response[CMUTCP].ack_num}"
                )
                print("Test Failed")
                return

            print("Test Passed")
        finally:
            try:
                conn.run(STOP_CLIENT_CMD, hide=True)
            except Exception:
                pass

def test_listener_single_syn():
    """Check that a freshly-started listener responds to a valid SYN with
    a correct SYN-ACK."""
    print("Running test_listener_single_syn()")

    START_SERVER_CMD = (
        "tmux new -s pytest_server_single -d "
        "/vagrant/project-2_15-441/server"
    )
    STOP_SERVER_CMD = "tmux kill-session -t pytest_server_single"

    with Connection(
        host=TESTING_HOST_IP,
        user="vagrant",
        connect_kwargs={"password": "vagrant"},
    ) as conn:
        try:
            conn.run(START_SERVER_CMD)
            conn.run("tmux has-session -t pytest_server_single")

            my_isn = 1000
            my_port = 23456  # arbitrary distinct port for this test

            my_udp = UDP(sport=my_port, dport=TESTING_HOST_PORT)
            syn_pkt = (
                ip /
                my_udp /
                CMUTCP(
                    plen=25,
                    seq_num=my_isn,
                    ack_num=0,
                    flags=SYN_MASK,
                    source_port=my_port,
                    destination_port=TESTING_HOST_PORT,
                )
            )
            send(syn_pkt, iface=IFNAME)

            synack_candidates = sniff(
                iface=IFNAME,
                lfilter=lambda p: (
                    CMUTCP in p
                    and IP in p
                    and p[IP].src == TESTING_HOST_IP
                ),
                count=1,
                timeout=TIMEOUT,
            )
            synack = synack_candidates[0] if synack_candidates else None

            if synack is None:
                print("Did not receive SYN+ACK packet (no response at all).")
                print("Test Failed")
                return

            print(
                f"Got response: flags={synack[CMUTCP].flags}, "
                f"seq={synack[CMUTCP].seq_num}, ack={synack[CMUTCP].ack_num}"
            )

            if synack[CMUTCP].flags != (SYN_MASK | ACK_MASK):
                print("Response does not have SYN+ACK flags set.")
                print("Test Failed")
                return
            if synack[CMUTCP].ack_num != my_isn + 1:
                print(f"Incorrect ack_num. Expected {my_isn + 1}.")
                print("Test Failed")
                return

            print("Test Passed")
        finally:
            try:
                conn.run(STOP_SERVER_CMD, hide=True)
            except Exception:
                pass

if __name__ == "__main__":
    test_pcap_packets_max_size()
    test_pcap_acks()
    test_run_server_client()
    test_basic_retransmit()
    test_initiator_single_data_packet()
    test_listener_single_syn()
    pass
