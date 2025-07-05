#!/usr/bin/awk -f
# Trace complete audio path from source through relay to final destination
# Usage: awk -f trace_audio_path.awk logfile.json

BEGIN {
    print "Audio Path Tracing"
    print "=================="
    print ""
    
    # Focus on audio-lab pods
    audio_pattern = "audio-lab"
}

# Process audio signature events from audio-lab namespace
/"audio_signature"/ && /audio-lab/ {
    # Extract all fields
    signature = extract_field("signature")
    src_pod = extract_field("src_pod")
    dst_pod = extract_field("dst_pod")
    src_ip = extract_field("src_ip")
    dst_ip = extract_field("dst_ip")
    src_port = extract_field("src_port")
    dst_port = extract_field("dst_port")
    src_namespace = extract_field("src_namespace")
    dst_namespace = extract_field("dst_namespace")
    timestamp_human = extract_field("timestamp_human")
    
    # Track signatures by their path
    if (signature != "") {
        # Create hop identifier
        hop = src_pod ":" src_port " -> " dst_ip ":" dst_port
        if (dst_pod != "unknown" && dst_pod != "") {
            hop = src_pod ":" src_port " -> " dst_pod ":" dst_port
        }
        
        # Store hop for this signature
        if (!(signature in signature_paths)) {
            signature_paths[signature] = hop
            signature_first_seen[signature] = timestamp_human
        } else if (index(signature_paths[signature], hop) == 0) {
            signature_paths[signature] = signature_paths[signature] " | " hop
        }
        
        signature_count[signature]++
        
        # Track unique destinations from relay
        if (index(src_pod, "relay") > 0) {
            relay_dst = dst_ip ":" dst_port
            relay_destinations[relay_dst]++
            if (!(relay_dst in relay_dst_first)) {
                relay_dst_first[relay_dst] = timestamp_human
            }
        }
    }
}

END {
    # Show relay destinations
    print "Destinations from Audio Relay"
    print "-----------------------------"
    printf "%-25s %-8s %-30s %s\n", "Destination", "Count", "First Seen", "Type"
    
    for (dst in relay_destinations) {
        port = dst
        sub(/.*:/, "", port)
        
        # Guess destination type by port
        type = "Unknown"
        if (port == "443") type = "HTTPS (Browser/Ingress)"
        else if (port == "80") type = "HTTP"
        else if (port == "8000" || port == "8001") type = "Audio Service"
        else if (port == "8900") type = "Possible Ingress/Service"
        else if (port > 30000) type = "NodePort/High Port"
        
        printf "%-25s %-8d %-30s %s\n", dst, relay_destinations[dst], relay_dst_first[dst], type
    }
    
    print ""
    print "Sample Audio Signature Paths"
    print "----------------------------"
    
    # Show paths for signatures that traverse multiple hops
    shown = 0
    for (sig in signature_paths) {
        path = signature_paths[sig]
        hop_count = split(path, hops, " | ")
        
        if (hop_count > 1 && shown < 10) {
            print ""
            print "Signature: " sig " (seen " signature_count[sig] " times)"
            print "First seen: " signature_first_seen[sig]
            print "Path:"
            
            for (i = 1; i <= hop_count; i++) {
                print "  " i ". " hops[i]
            }
            shown++
        }
    }
    
    # Summary statistics
    print ""
    print "Summary"
    print "-------"
    
    total_sigs = 0
    multi_hop = 0
    for (sig in signature_paths) {
        total_sigs++
        if (split(signature_paths[sig], hops, " | ") > 1) {
            multi_hop++
        }
    }
    
    print "Total unique signatures from audio-lab: " total_sigs
    print "Signatures with multiple hops: " multi_hop
    print "Unique relay destinations: " length(relay_destinations)
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