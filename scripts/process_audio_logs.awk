#!/usr/bin/awk -f
# Process audio latency tracker logs into CSV format
# Usage: awk -f process_audio_logs.awk logfile.json

BEGIN {
    # Print CSV header
    print "Signature,First_Seen,Last_Seen,Duration_ms,Observations,Source_Pods,Destination_Pods,Source_IPs,Destination_IPs"
    
    # Initialize variables
    FS = ":"
    OFS = ","
}

# Process JSON log lines containing audio_signature events
/audio_signature/ {
    # Extract JSON fields using simple pattern matching
    signature = extract_field("signature")
    timestamp_human = extract_field("timestamp_human")
    src_pod = extract_field("src_pod")
    dst_pod = extract_field("dst_pod")
    src_ip = extract_field("src_ip")
    dst_ip = extract_field("dst_ip")
    
    # Skip if we couldn't extract signature
    if (signature == "") next
    
    # Convert timestamp to epoch for calculations
    timestamp_epoch = timestamp_to_epoch(timestamp_human)
    
    # Initialize signature data if first time seeing it
    if (!(signature in signatures)) {
        signatures[signature] = 1
        first_seen[signature] = timestamp_epoch
        first_seen_human[signature] = timestamp_human
        last_seen[signature] = timestamp_epoch
        last_seen_human[signature] = timestamp_human
        observations[signature] = 0
        
        # Initialize arrays for this signature
        src_pods[signature] = ""
        dst_pods[signature] = ""
        src_ips[signature] = ""
        dst_ips[signature] = ""
    }
    
    # Update observation data
    observations[signature]++
    
    # Update last seen time
    if (timestamp_epoch > last_seen[signature]) {
        last_seen[signature] = timestamp_epoch
        last_seen_human[signature] = timestamp_human
    }
    
    # Collect unique source pods
    if (src_pod != "unknown" && src_pod != "" && index(src_pods[signature], src_pod) == 0) {
        if (src_pods[signature] != "") src_pods[signature] = src_pods[signature] ","
        src_pods[signature] = src_pods[signature] src_pod
    }
    
    # Collect unique destination pods
    if (dst_pod != "unknown" && dst_pod != "" && index(dst_pods[signature], dst_pod) == 0) {
        if (dst_pods[signature] != "") dst_pods[signature] = dst_pods[signature] ","
        dst_pods[signature] = dst_pods[signature] dst_pod
    }
    
    # Collect unique source IPs
    if (src_ip != "" && index(src_ips[signature], src_ip) == 0) {
        if (src_ips[signature] != "") src_ips[signature] = src_ips[signature] ","
        src_ips[signature] = src_ips[signature] src_ip
    }
    
    # Collect unique destination IPs
    if (dst_ip != "" && index(dst_ips[signature], dst_ip) == 0) {
        if (dst_ips[signature] != "") dst_ips[signature] = dst_ips[signature] ","
        dst_ips[signature] = dst_ips[signature] dst_ip
    }
}

END {
    # Print CSV rows for each signature with 2+ observations
    for (sig in signatures) {
        # Only include signatures seen 2 or more times
        if (observations[sig] < 2) continue
        
        # Calculate duration in milliseconds
        duration_ms = (last_seen[sig] - first_seen[sig]) * 1000
        
        # Format CSV output - escape quotes and commas in field values
        printf "%s,%s,%s,%.2f,%d,%s,%s,%s,%s\n",
            escape_csv(sig),
            escape_csv(first_seen_human[sig]),
            escape_csv(last_seen_human[sig]),
            duration_ms,
            observations[sig],
            escape_csv(src_pods[sig] != "" ? src_pods[sig] : "unknown"),
            escape_csv(dst_pods[sig] != "" ? dst_pods[sig] : "unknown"),
            escape_csv(src_ips[sig] != "" ? src_ips[sig] : "unknown"),
            escape_csv(dst_ips[sig] != "" ? dst_ips[sig] : "unknown")
    }
    
    # Print summary to stderr so it doesn't interfere with CSV output
    print "# Summary:" > "/dev/stderr"
    print "# Total unique signatures: " length(signatures) > "/dev/stderr"
    print "# Total observations: " total_observations() > "/dev/stderr"
}

# Helper function to extract JSON field value
function extract_field(field_name) {
    # Look for "field_name": value pattern
    pattern = "\"" field_name "\":[[:space:]]*\"?([^,}\"]*)"
    if (match($0, pattern, arr)) {
        # Remove quotes if present
        gsub(/^"/, "", arr[1])
        gsub(/"$/, "", arr[1])
        return arr[1]
    }
    return ""
}

# Convert ISO timestamp to epoch seconds (simplified)
function timestamp_to_epoch(timestamp) {
    # This is a simplified conversion - in practice you might want to use a more robust method
    # For now, we'll use a simple hash of the timestamp for relative ordering
    return length(timestamp) + index(timestamp, "T") * 1000
}

# Calculate total observations
function total_observations() {
    total = 0
    for (sig in observations) {
        total += observations[sig]
    }
    return total
}

# Escape CSV field values - wrap in quotes if contains comma or quote
function escape_csv(value) {
    if (index(value, ",") > 0 || index(value, "\"") > 0) {
        # Escape quotes by doubling them
        gsub(/"/, "\"\"", value)
        return "\"" value "\""
    }
    return value
}