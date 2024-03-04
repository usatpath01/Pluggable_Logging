import sys
import re
import json
import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
import copy

    
        

# Assume that connects come from different IPs

if __name__ == "__main__":
# Check if the user provided a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <log_file>")
        sys.exit(1)

    # Get the log file path from the command-line argument
    log_file_path = sys.argv[1]
    
    
    edges = []
    nodes = {}
    node_file_details = {}
    node_reverse_map = {}
    file_reverse_map = {} # (host_id, host_pid, host_tid,fd) -> node id
    deleted_files_map = {} # (dirfd, path) -> node id
    
    connections_map = {} # (server_IP, server_Port) -> (client IP, client port) 
    ip_port_id_map = {} #(ip,port) -> node id
    
    clone_map = {} # (Host #, host pid, retval tid, type (p:0 or c:1)) -> node id
    
    existing_binaries = {} # (name) -> node id
    
        
    node_counter = 1 
    
    nodes[node_counter] = {
        "type" : "exit"
    }
    node_counter = node_counter + 1 
    nodes[node_counter] = {
        "type" : "error"
    }
    node_counter = node_counter + 1 
    
    # Read each line from the log file
    with open(log_file_path, 'r') as file:
        for line in file:
            # Check if the line starts with "Host"
            line = line.strip()
            if line.startswith("Host"):
                try:
                    line = line + ","
                    line = ''.join(line.rsplit(',', 1))
                    host_id = int(line.split(" ")[1])
                    json_data = json.loads(line.split(":", 1)[1].strip())
                    host_pid = json_data["event_context"]["task_context"]["host_pid"]
                    host_tid = json_data["event_context"]["task_context"]["host_tid"]
                    timestamp = json_data["event_context"]["ts"]
                    
                    if "syscall_name" not in json_data["event_context"]: # Not a system call log
                        continue                        
                    
                    if (host_id, host_pid, host_tid) not in node_reverse_map:
                        node_reverse_map[(host_id, host_pid, host_tid)] = node_counter
                        nodes[node_counter] = {
                            "type": "process",
                            "host_id":host_id, 
                            "host_pid":host_pid, 
                            "host_tid":host_tid, 
                            "task_command":json_data["event_context"]["task_context"]["task_command"]
                            }
                        node_file_details[node_counter] = {}
                        node_counter = node_counter + 1
                    
                    
                    
                    syscall_name = json_data["event_context"]["syscall_name"]
                    current_node_id = node_reverse_map[(host_id, host_pid, host_tid)]
                    
                    if (syscall_name != "exit") and (int(json_data["event_context"]["retval"]) < 0):
                        edges.append((current_node_id, 2 ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        continue
                        
                    
                    if (syscall_name == "open") or ((syscall_name == "openat")):
                        retval = json_data["event_context"]["retval"]
                        filename = json_data["arguments"]["filename"]
                        if (host_id, host_pid, host_tid,retval) not in file_reverse_map:
                            file_reverse_map[(host_id, host_pid, host_tid,retval)] = node_counter
                            nodes[node_counter] = {
                                "type":"file",
                                "file_name":filename
                                }
                            node_counter = node_counter + 1
                        file_node_id = file_reverse_map[(host_id, host_pid, host_tid,retval)]
                        node_file_details[current_node_id][retval] = file_node_id
                        edges.append((current_node_id, file_node_id,{"syscall":"open", "timestamp":timestamp}))
                    
                    if (syscall_name == "read") :
        
                        file_desc = json_data["arguments"]["fd"]
                        filename = json_data["artifacts"]["file_read"]
                        if file_desc not in node_file_details[current_node_id]:
                            # Create file node 
                            file_reverse_map[(host_id, host_pid, host_tid,file_desc)] = node_counter
                            nodes[node_counter] = {
                                "type":"file",
                                "file_name":filename
                                }
                            node_counter = node_counter + 1
                            # Assign to current process
                            file_node_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                            node_file_details[current_node_id][file_desc] = file_node_id
                            
                        edges.append((current_node_id, node_file_details[current_node_id][file_desc] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                    
                    if (syscall_name == "write") :
        
                        file_desc = json_data["arguments"]["fd"]
                        filename = json_data["artifacts"]["file_written"]
                        
                        if file_desc not in node_file_details[current_node_id]:
                            # Create file node 
                            file_reverse_map[(host_id, host_pid, host_tid,file_desc)] = node_counter
                            nodes[node_counter] = {
                                "type":"file",
                                "file_name":filename
                                }
                            node_counter = node_counter + 1
                            # Assign to current process
                            file_node_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                            node_file_details[current_node_id][file_desc] = file_node_id
                            
                        edges.append((current_node_id, node_file_details[current_node_id][file_desc] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        
                    if (syscall_name == "close") :
                        file_desc = json_data["arguments"]["fd"]
                        
                        if file_desc not in node_file_details[current_node_id]:
                            # Create file node 
                            file_reverse_map[(host_id, host_pid, host_tid, file_desc)] = node_counter
                            nodes[node_counter] = {
                                "type":"file",
                                "file_name":"unknown"
                                }
                            node_counter = node_counter + 1
                            # Assign to current process
                            file_node_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                            node_file_details[current_node_id][file_desc] = file_node_id
                        edges.append((current_node_id, node_file_details[current_node_id][file_desc] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        if (host_id, host_pid, host_tid, file_desc) in file_reverse_map:
                            file_reverse_map.pop((host_id, host_pid, host_tid, file_desc))
                        node_file_details[current_node_id].pop(file_desc)
                        
                    if (syscall_name == "dup") :
                        file_desc = json_data["arguments"]["fildes"]
                        new_file_desc = json_data["event_context"]["retval"]                      
                        if file_desc not in node_file_details[current_node_id]:
                            # Create file node 
                            file_reverse_map[(host_id, host_pid, host_tid, file_desc)] = node_counter
                            nodes[node_counter] = {
                                "type":"file",
                                "file_name":"unknown"
                                }
                            node_counter = node_counter + 1
                            # Assign to current process
                            file_node_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                            node_file_details[current_node_id][file_desc] = file_node_id
                        
                        old_file_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                        
                        # Create new file node 
                        file_reverse_map[(host_id, host_pid, host_tid, new_file_desc)] = node_counter
                        nodes[node_counter] = {
                            "type":"file",
                            "file_name":f"{nodes[old_file_id]['file_name']}"
                            }
                        node_counter = node_counter + 1
                        # Assign to current process
                        new_file_node_id = file_reverse_map[(host_id, host_pid, host_tid,new_file_desc)]
                        node_file_details[current_node_id][new_file_desc] = new_file_node_id
                
                        edges.append((current_node_id, old_file_id ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        edges.append((old_file_id, new_file_node_id ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        
                    
                    if (syscall_name == "dup2") or (syscall_name == "dup3") :
                        file_desc = json_data["arguments"]["oldfd"]
                        new_file_desc = json_data["arguments"]["newfd"]                      
                        if file_desc not in node_file_details[current_node_id]:
                            # Create file node 
                            file_reverse_map[(host_id, host_pid, host_tid, file_desc)] = node_counter
                            nodes[node_counter] = {
                                "type":"file",
                                "file_name":"unknown"
                                }
                            node_counter = node_counter + 1
                            # Assign to current process
                            file_node_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                            node_file_details[current_node_id][file_desc] = file_node_id
                        
                        old_file_id = file_reverse_map[(host_id, host_pid, host_tid,file_desc)]
                        
                        if new_file_desc in node_file_details[current_node_id]:
                            node_file_details[current_node_id].pop(new_file_desc)
                        
                        if (host_id, host_pid, host_tid, new_file_desc) in file_reverse_map:
                            file_reverse_map.pop((host_id, host_pid, host_tid, new_file_desc))
                            
                        # Create new file node 
                        file_reverse_map[(host_id, host_pid, host_tid, new_file_desc)] = node_counter
                        nodes[node_counter] = {
                            "type":"file",
                            "file_name":f"{nodes[old_file_id]['file_name']}"
                            }
                        node_counter = node_counter + 1
                        # Assign to current process
                        new_file_node_id = file_reverse_map[(host_id, host_pid, host_tid,new_file_desc)]
                        node_file_details[current_node_id][new_file_desc] = new_file_node_id
                        
                        edges.append((current_node_id, old_file_id ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        edges.append((old_file_id, new_file_node_id ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        
                    if (syscall_name == "unlinkat") :
                        dirfd = json_data["arguments"]["dfd"]
                        pathname = json_data["arguments"]["pathname"]
                        
                        
                        if (dirfd, pathname) not in deleted_files_map:
                            nodes[node_counter] = {
                                "type":"deleted_file",
                                "pathname":f"{pathname}",
                                "dirfd":f"{dirfd}"
                                }
                            deleted_files_map[(dirfd,pathname)] = node_counter
                            node_counter = node_counter+1               
                        edges.append((current_node_id, deleted_files_map[((dirfd,pathname))] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        
                        
                    if syscall_name == "socket":
                        sockfd = json_data["event_context"]["retval"]
                        nodes[node_counter] = {
                                "type":"unbound_socket",
                                "sockfd":f"{sockfd}"
                                }
                        file_reverse_map[(host_id, host_pid, host_tid,sockfd)] = node_counter
                        node_counter = node_counter + 1
                        edges.append((current_node_id, file_reverse_map[(host_id, host_pid, host_tid,sockfd)] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        node_file_details[current_node_id][sockfd] = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                        print("DONE Socket")
                        
                    if syscall_name == "bind":
                        
                        sockfd = json_data["arguments"]["fd"]
                        ip_address = json_data["artifacts"]["IP"]
                        port = json_data["artifacts"]["port"]

                        old_counter = -1
                        if (host_id, host_pid, host_tid,sockfd) in file_reverse_map :
                            old_counter = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                            file_reverse_map.pop((host_id, host_pid, host_tid,sockfd))
                        nodes[node_counter] = {
                                "type":"bound_socket",
                                "IP":ip_address,
                                "port":port
                                }
                        file_reverse_map[(host_id, host_pid, host_tid,sockfd)] = node_counter
                        node_counter = node_counter + 1
                        if old_counter != -1:
                            edges.append((current_node_id, old_counter ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                            edges.append((old_counter, file_reverse_map[(host_id, host_pid, host_tid,sockfd)] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        node_file_details[current_node_id][sockfd] = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                        print("DONE Bind")
                    
                    if (syscall_name == "accept") or (syscall_name == "accept4") :
                        sockfd = json_data["event_context"]["retval"]
                        ip_address = json_data["artifacts"]["IP"]
                        port = json_data["artifacts"]["port"]
                        oldfd = json_data["arguments"]["fd"]
                        
                        nodes[node_counter] = {
                                "type":"connected_socket",
                                "connected to IP":ip_address,
                                "connected to port":port,
                                "sockfd":f"{sockfd}",
                                "own IP": nodes[file_reverse_map[(host_id, host_pid, host_tid,oldfd)]]["IP"],
                                "own port":nodes[file_reverse_map[(host_id, host_pid, host_tid,oldfd)]]["port"]
                                }
                        ip_port_id_map[(nodes[file_reverse_map[(host_id, host_pid, host_tid,oldfd)]]["IP"], nodes[file_reverse_map[(host_id, host_pid, host_tid,oldfd)]]["port"], ip_address,port)] = node_counter
                        file_reverse_map[(host_id, host_pid, host_tid,sockfd)] = node_counter
                        node_counter = node_counter + 1
                        socket_id = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                        
                        # Assuming only bound sockets can accept
                        bound_socket_id = file_reverse_map[(host_id, host_pid, host_tid,oldfd)]
                        bound_socket_ip = nodes[bound_socket_id]["IP"]
                        bound_socket_port = nodes[bound_socket_id]["port"]
                        
                        # accept calls are dealt with before connect
                        connections_map[(bound_socket_ip, bound_socket_port)] = (ip_address, port)
                        
                        edges.append((current_node_id, bound_socket_id ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        edges.append((bound_socket_id,  file_reverse_map[(host_id, host_pid, host_tid,sockfd)] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        node_file_details[current_node_id][sockfd] = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                        print("DONE Accept")   
                        
                    if syscall_name == "connect": 
                        client_sockfd = json_data["arguments"]["fd"]
                        server_ip = json_data["artifacts"]["IP"]
                        server_port = json_data["artifacts"]["port"]
                        
                        old_counter = file_reverse_map[(host_id, host_pid, host_tid,client_sockfd)]
                        
                        if (server_ip, server_port) not in connections_map:
                            continue 
                        
                        client_ip = connections_map[(server_ip,server_port)][0]
                        client_port = connections_map[((server_ip,server_port))][1]
                        
                        nodes[node_counter] = {
                                "type":"connected_socket",
                                "connected to IP":server_ip,
                                "connected to port":server_port,
                                "sockfd":f"{client_sockfd}",
                                "own IP": client_ip,
                                "own port":client_port
                                }
                        ip_port_id_map[(client_ip, client_port, server_ip,server_port)] = node_counter
                        file_reverse_map[(host_id, host_pid, host_tid,client_sockfd)] = node_counter
                        node_counter = node_counter + 1
                        
                        edges.append((current_node_id, old_counter ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        edges.append((old_counter,  file_reverse_map[(host_id, host_pid, host_tid,client_sockfd)] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        node_file_details[current_node_id][client_sockfd] = file_reverse_map[(host_id, host_pid, host_tid,client_sockfd)]
                        print("DONE Connect")
                    
                    if syscall_name == "send": 
                        sockfd = json_data["arguments"]["sockfd"]
                        node_id = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                        if nodes[node_id]["type"] != "connected_socket":
                            continue
                        
                        send_to_IP = nodes[node_id]["connected to IP"]
                        send_to_port = nodes[node_id]["connected to port"]
                        
                        own_IP = nodes[node_id]["own IP"]
                        own_port = nodes[node_id]["own port"]
                        edges.append((ip_port_id_map[(own_IP,own_port,send_to_IP,send_to_port)], ip_port_id_map[(send_to_IP,send_to_port,own_IP,own_port)] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        print("DONE send")
                        
                    if syscall_name == "recv": 
                        sockfd = json_data["arguments"]["sockfd"]
                        node_id = file_reverse_map[(host_id, host_pid, host_tid,sockfd)]
                        if nodes[node_id]["type"] != "connected_socket":
                            continue
                        recv_from_IP = nodes[node_id]["connected to IP"]
                        recv_from_port = nodes[node_id]["connected to port"]
                        own_IP = nodes[node_id]["own IP"]
                        own_port = nodes[node_id]["own port"]
                        
                        edges.append((ip_port_id_map[(own_IP,own_port,recv_from_IP,recv_from_port)], ip_port_id_map[(recv_from_IP,recv_from_port,own_IP,own_port)] ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        print("DONE recv")
                
                    if (syscall_name == "clone") or (syscall_name == "fork") or (syscall_name == "vfork"):
                        retval = int(json_data["event_context"]["retval"])                        
                        if retval != 0: # Parent process
                            if (host_id,host_pid,retval,1) not in clone_map: # Parent log coming first
                                clone_map[(host_id,host_pid,retval,0)] = current_node_id
                                continue
                            else:
                                edges.append((current_node_id ,clone_map[(host_id, parent_host_pid, current_tid,1)], {"syscall":f"{syscall_name}", "timestamp":timestamp}))
                                node_file_details[clone_map[(host_id, parent_host_pid, current_tid,1)]] = copy.deepcopy(node_file_details[current_node_id])
                                clone_map.pop((host_id, parent_host_pid, current_tid,1))
                                continue
                            
                        parent_host_pid = json_data["event_context"]["task_context"]["host_ppid"]
                        current_tid = json_data["event_context"]["task_context"]["tid"]   
                        if (host_id, parent_host_pid, current_tid,0) in clone_map:
                            edges.append((clone_map[(host_id, parent_host_pid, current_tid,0)], current_node_id ,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                            node_file_details[current_node_id] = copy.deepcopy(node_file_details[clone_map[(host_id, parent_host_pid, current_tid,0)]])
                            clone_map.pop((host_id, parent_host_pid, current_tid,0))
                        else:
                            clone_map[(host_id, parent_host_pid, current_tid,1)] = current_node_id
                        print("clone done")
                    
                    if syscall_name == "execve":
                        binary_filename = json_data["arguments"]["filename"]
                        if (binary_filename) not in existing_binaries:
                            nodes[node_counter] = {
                                "type":"binary",
                                "filename":binary_filename
                            }
                            existing_binaries[binary_filename] = node_counter
                            node_counter = node_counter+1
                        binary_id = existing_binaries[binary_filename]
                        edges.append((current_node_id,binary_id,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        print("execve done")
                
                    if syscall_name == "exit":
                        edges.append((current_node_id,1,{"syscall":f"{syscall_name}", "timestamp":timestamp}))
                        
                except (json.JSONDecodeError, KeyError) as e:
                    # print(f"Error extracting data from line: {line.strip()}, {e}")
                    
                    continue
                except Exception as e:
                    # print(f"Error processing line: {line.strip()}, {e}")
                    continue
    
    # # Create an empty graph
    # G = nx.MultiDiGraph()
    # G.add_nodes_from(nodes.keys())
    # G.add_edges_from(edges)
    # # Calculate node sizes based on the length of the text
    # node_sizes = [3000 + len(props['type']) * 300 for _, props in nodes.items()]
    
    # # Draw the graph
    # pos = nx.spring_layout(G, k=0.5)  # positions for all nodes with reduced spring constant
    # # Draw nodes with labels
    # # Draw nodes with labels
    # file_nodes = [node for node, props in nodes.items() if props.get('type') == 'file']
    # process_nodes = [node for node, props in nodes.items() if props.get('type') == 'process']
    # nx.draw_networkx_nodes(G, pos, nodelist=file_nodes, node_color='orange', node_size=3000)
    # nx.draw_networkx_nodes(G, pos, nodelist=process_nodes, node_color='blue', node_size=3000)
    # nx.draw_networkx_labels(G, pos, labels={node: f"{props['type']} node \nHost : {props.get('host_id', '')}\n Host pid: {props.get('host_pid', '')} \nHost tid : {props.get('host_tid', '')} \n Task Command : {props.get('task_command', '')}" for node, props in nodes.items() if props.get('type') == 'process'}, font_size=8, font_color='black')
    # nx.draw_networkx_labels(G, pos, labels={node: f"{props['type']} node \n filename : {props.get('file_name','')}" for node, props in nodes.items() if props.get('type') == 'file'}, font_size=8, font_color='black')

    # # # Draw edges with reduced alpha
    # # nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.8)

    # # Add edge labels
    # edge_labels = {(u, v): props['syscall'] for u, v, props in edges}
    # nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='blue')
    # # Calculate figure size based on the size of text
    # max_text_length = max(len(props['type']) for props in nodes.values())
    # fig_width = max_text_length * 3
    # fig_height = len(nodes) * 3

    # ax = plt.gca()
    # for e in G.edges(data = True, keys = True):
    #     ax.annotate("",
    #                 xy=pos[e[0]], xycoords='data',
    #                 xytext=pos[e[1]], textcoords='data',
    #                 arrowprops=dict(arrowstyle="->", color="0.5",
    #                                 shrinkA=5, shrinkB=5,
    #                                 patchA=None, patchB=None,
    #                                 connectionstyle="arc3,rad=rrr".replace('rrr',str(0.1*e[2])
    #                                 ),
    #                                 ),
    #     )

    # # Save the plot
    # plt.title("Graph with Nodes and Edges")
    # plt.gcf().set_size_inches(fig_width, fig_height)  # Adjust figure size
    # plt.axis('off')
    # plt.tight_layout()
    # plt.savefig("final_graph.png")  # Save as PNG file
    
    # Create a Pyvis Network object
    net = Network(height="500px", width="100%", notebook=True, directed=True, cdn_resources='in_line')
    # Add nodes to the network using the keys of the dictionary
    # for node_id in nodes.keys():
    #     net.add_node(node_id, label=nodes[node_id])
    # Add nodes to the network
    for node_id, props in nodes.items():
        if props['type'] == 'process':
            net.add_node(node_id, label=f"{props['type']} node \nHost : {props.get('host_id', '')}\n Host pid: {props.get('host_pid', '')} \nHost tid : {props.get('host_tid', '')} \n Task Command : {props.get('task_command', '')}", color='orange')
        elif props['type'] == 'deleted_file':
            net.add_node(node_id, label=f"{props['type']} node \n pathname : {props.get('pathname','')} \n dirfd: {props.get('dirfd','')}", color='#B9BAA3')
        elif props['type'] == 'unbound_socket':
            net.add_node(node_id, label=f"{props['type']} node \n sockfd : {props.get('sockfd','')}", color='#07BEB8')
        elif props['type'] == 'bound_socket':
            net.add_node(node_id, label=f"{props['type']} node \n IP : {props.get('IP','')} \n port: {props.get('port','')}", color='#8F3985')
        elif props['type'] == 'connected_socket':
            net.add_node(node_id, label=f"{props['type']} node \n connected to IP : {props.get('connected to IP','')} \n connected to port: {props.get('connected to port','')}, \n own IP: {props.get('own IP','')}, \n own port: {props.get('own port','')}", color='#25283D')
        elif props['type'] == 'binary':
            net.add_node(node_id, label = f"{props['type']} node \n filename : {props['filename']}", color="#00AF54")
        elif props['type'] == 'error':
            net.add_node(node_id, label = f"{props['type']} node" , color="red")
        elif props['type'] == 'exit':
            net.add_node(node_id, label = f"{props['type']} node", color="black")
        else:
            net.add_node(node_id, label=f"{props['type']} node \n filename : {props.get('file_name','')}\n")
        
    for u,v,dicti in edges:
        net.add_edge(u,v,label = f"{dicti['syscall']}, {dicti['timestamp']}")
        
    # Set the layout algorithm to spread out the graph more
    net.barnes_hut()
    # Other layout options you can try: 'force_atlas_2based', 'force', 'networkx', etc.

    # Show the network
    net.set_edge_smooth('dynamic')
    net.show("graph_syscall.html")
