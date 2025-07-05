#!/usr/bin/awk -f
# Map edge IPs to system names based on traffic patterns
# Usage: awk -f map_edge_ips.awk logfile.json

BEGIN {
    # Known system IPs
    ip_names["169.254.169.254"] = "AWS-Metadata-Service"
    ip_names["192.168.106.206"] = "Kubernetes-API-Endpoint"
    ip_names["192.168.91.223"] = "Kubernetes-API-Endpoint"
    
    print "Edge IP Mapping Analysis"
    print "========================"
    print ""
}

# Process audio events to unknown destinations
/"audio_signature"/ && /"dst_pod":"unknown"/ {
    dst_ip = extract_field("dst_ip")
    dst_port = extract_field("dst_port")
    src_pod = extract_field("src_pod")
    src_port = extract_field("src_port")
    
    if (dst_ip != "") {
        # Track what pods send to each edge IP
        edge_sources[dst_ip] = edge_sources[dst_ip] " " src_pod
        edge_ports[dst_ip] = edge_ports[dst_ip] " " dst_port
        edge_count[dst_ip]++
        
        # Track specific flows
        flow = src_pod ":" src_port " -> " dst_ip ":" dst_port
        flow_count[flow]++
    }
}

END {
    # Analyze patterns to determine edge IP roles
    for (ip in edge_count) {
        # Skip if already known
        if (ip in ip_names) continue
        
        # Analyze source pods
        split(edge_sources[ip], sources, " ")
        audio_relay_count = 0
        audio_source_count = 0
        other_count = 0
        
        for (i in sources) {
            if (index(sources[i], "audio-relay") > 0) audio_relay_count++
            else if (index(sources[i], "audio-source") > 0) audio_source_count++
            else if (sources[i] != "") other_count++
        }
        
        # Analyze destination ports
        split(edge_ports[ip], ports, " ")
        high_port_count = 0
        audio_port_count = 0
        
        for (i in ports) {
            port_num = int(ports[i])
            if (port_num > 30000) high_port_count++
            if (port_num == 8000 || port_num == 8001 || port_num == 8900) audio_port_count++
        }
        
        # Determine IP role based on patterns
        if (audio_relay_count > audio_source_count && audio_relay_count > other_count) {
            if (high_port_count > audio_port_count) {
                ip_names[ip] = "ALB-Internal-IP (Browser Traffic)"
            } else {
                ip_names[ip] = "ALB-Internal-IP (Audio Service)"
            }
        } else if (other_count > audio_relay_count) {
            ip_names[ip] = "Kubernetes-System-Service"
        } else {
            ip_names[ip] = "Unknown-Edge-IP"
        }
    }
    
    # Print edge IP summary with names
    print "Edge IPs with Identified Roles:"
    print "-------------------------------"
    printf "%-20s %-35s %-10s %s\n", "IP Address", "Identified As", "Events", "Primary Sources"
    
    for (ip in edge_count) {
        name = (ip in ip_names) ? ip_names[ip] : "Unknown"
        
        # Get primary source
        split(edge_sources[ip], sources, " ")
        primary_source = ""
        for (i in sources) {
            if (sources[i] != "" && index(primary_source, sources[i]) == 0) {
                if (primary_source != "") primary_source = primary_source ", "
                primary_source = primary_source sources[i]
                if (length(primary_source) > 40) {
                    primary_source = substr(primary_source, 1, 37) "..."
                    break
                }
            }
        }
        
        printf "%-20s %-35s %-10d %s\n", ip, name, edge_count[ip], primary_source
    }
    
    print ""
    print "Audio Traffic to Edge (ALB):"
    print "----------------------------"
    
    # Show only audio-relay to edge flows
    for (flow in flow_count) {
        if (index(flow, "audio-relay") > 0 && flow_count[flow] > 10) {
            split(flow, parts, " -> ")
            dst = parts[2]
            split(dst, dst_parts, ":")
            dst_ip = dst_parts[1]
            
            if (dst_ip in ip_names && index(ip_names[dst_ip], "ALB") > 0) {
                printf "%-60s %6d events -> %s\n", flow, flow_count[flow], ip_names[dst_ip]
            }
        }
    }
}

function extract_field(field_name) {
    pattern = "\"" field_name "\":[[:space:]]*\"?([^,}\"]*)"
    if (match($0, pattern, arr)) {
        gsub(/^"/, "", arr[1])
        gsub(/"$/, "", arr[1])
        return arr[1]
    }
    return ""
}