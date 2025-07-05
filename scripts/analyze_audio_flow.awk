#!/usr/bin/awk -f
# Analyze audio flow patterns by destination port and pod type
# Usage: awk -f analyze_audio_flow.awk logfile.json

BEGIN {
    print "Audio Flow Analysis"
    print "==================="
    print ""
}

# Process audio signature events
/"audio_signature"/ {
    # Extract fields
    signature = extract_field("signature")
    src_pod = extract_field("src_pod")
    dst_pod = extract_field("dst_pod")
    src_ip = extract_field("src_ip")
    dst_ip = extract_field("dst_ip")
    src_port = extract_field("src_port")
    dst_port = extract_field("dst_port")
    
    # Track flows by destination port
    if (dst_port != "") {
        port_counts[dst_port]++
        
        # Track pod types for each port
        if (dst_pod != "" && dst_pod != "unknown") {
            port_pods[dst_port] = port_pods[dst_port] " " dst_pod
        } else {
            port_pods[dst_port] = port_pods[dst_port] " " dst_ip
        }
    }
    
    # Track source to destination patterns
    src_name = (src_pod != "" && src_pod != "unknown") ? src_pod : src_ip
    dst_name = (dst_pod != "" && dst_pod != "unknown") ? dst_pod : (dst_ip ":" dst_port)
    
    flow_key = src_name " -> " dst_name
    flow_counts[flow_key]++
    
    # Track signatures per flow
    flow_signatures[flow_key] = flow_signatures[flow_key] " " signature
    
    total_events++
}

END {
    if (total_events == 0) {
        print "No audio signature events found"
        exit 0
    }
    
    # Port analysis
    print "Destination Ports"
    print "-----------------"
    printf "%-10s %-10s %s\n", "Port", "Count", "Destinations (sample)"
    
    # Sort ports by count
    n = asorti(port_counts, sorted_ports, "@val_num_desc")
    
    for (i = 1; i <= n && i <= 20; i++) {
        port = sorted_ports[i]
        count = port_counts[port]
        
        # Get unique destinations for this port
        split(port_pods[port], dests, " ")
        unique_dests = ""
        seen_dests = ""
        dest_count = 0
        
        for (j in dests) {
            if (dests[j] != "" && index(seen_dests, dests[j]) == 0) {
                if (dest_count < 3) {  # Show first 3 unique destinations
                    if (unique_dests != "") unique_dests = unique_dests ", "
                    # Shorten pod names for display
                    short_name = dests[j]
                    if (index(short_name, "audio-") > 0) {
                        gsub(/-[a-z0-9]{8,}/, "-*", short_name)
                    }
                    unique_dests = unique_dests short_name
                    dest_count++
                }
                seen_dests = seen_dests " " dests[j]
            }
        }
        
        if (dest_count > 3) unique_dests = unique_dests "..."
        
        printf "%-10s %-10d %s\n", port, count, unique_dests
    }
    
    print ""
    print "Top Audio Flows"
    print "---------------"
    printf "%-70s %-10s %s\n", "Flow", "Count", "Unique Signatures"
    
    # Sort flows by count
    n = asorti(flow_counts, sorted_flows, "@val_num_desc")
    
    for (i = 1; i <= n && i <= 15; i++) {
        flow = sorted_flows[i]
        count = flow_counts[flow]
        
        # Count unique signatures for this flow
        split(flow_signatures[flow], sigs, " ")
        unique_count = 0
        seen_sigs = ""
        
        for (j in sigs) {
            if (sigs[j] != "" && index(seen_sigs, sigs[j]) == 0) {
                unique_count++
                seen_sigs = seen_sigs " " sigs[j]
            }
        }
        
        # Shorten flow names for display
        display_flow = flow
        gsub(/-[a-z0-9]{8,}/, "-*", display_flow)
        
        # Truncate if too long
        if (length(display_flow) > 68) {
            display_flow = substr(display_flow, 1, 65) "..."
        }
        
        printf "%-70s %-10d %d\n", display_flow, count, unique_count
    }
    
    print ""
    print "Port Categories"
    print "---------------"
    
    # Categorize ports
    http_count = port_counts["80"] + port_counts["8080"] + port_counts["8000"] + port_counts["8001"]
    https_count = port_counts["443"]
    high_ports = 0
    
    for (port in port_counts) {
        if (port > 30000) high_ports += port_counts[port]
    }
    
    print "HTTP/Audio ports (80,8000,8001,8080): " http_count
    print "HTTPS port (443): " https_count  
    print "High ports (>30000): " high_ports
    print "Total events: " total_events
}

# Helper function to extract JSON field value
function extract_field(field_name) {
    pattern = "\"" field_name "\":[[:space:]]*\"?([^,}\"]*)"
    if (match($0, pattern, arr)) {
        gsub(/^"/, "", arr[1])
        gsub(/"$/, "", arr[1])
        return arr[1]
    }
    return ""
}