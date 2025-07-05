#!/usr/bin/awk -f
# Convert audio signature events to PlantUML sequence diagram
# Usage: awk -v signature=12345 -f signature_to_plantuml.awk logfile.json

BEGIN {
    if (!signature) {
        print "Error: Please specify signature with -v signature=VALUE" > "/dev/stderr"
        exit 1
    }
    
    # PlantUML header
    print "@startuml"
    print "title Audio Signature " signature " Flow"
    print "!theme plain"
    print ""
    
    # Track unique participants and their order
    participant_count = 0
    
    # Arrays to store events for sorting
    event_count = 0
}

# Process JSON log lines containing the specified signature
/"audio_signature"/ && match($0, "\"signature\":" signature "[^0-9]") {
    # Extract fields
    timestamp_ns = extract_field("timestamp_ns")
    timestamp_human = extract_field("timestamp_human")
    src_pod = extract_field("src_pod")
    dst_pod = extract_field("dst_pod")
    src_ip = extract_field("src_ip")
    dst_ip = extract_field("dst_ip")
    src_port = extract_field("src_port")
    dst_port = extract_field("dst_port")
    direction = extract_field("dir")
    
    # Create participant identifiers
    if (src_pod != "" && src_pod != "unknown") {
        src_name = src_pod
    } else {
        src_name = src_ip ":" src_port
    }
    
    if (dst_pod != "" && dst_pod != "unknown") {
        dst_name = dst_pod
    } else {
        dst_name = dst_ip ":" dst_port
    }
    
    # Add to participants if new
    if (!(src_name in participants)) {
        participants[src_name] = ++participant_count
        participant_order[participant_count] = src_name
    }
    
    if (!(dst_name in participants)) {
        participants[dst_name] = ++participant_count
        participant_order[participant_count] = dst_name
    }
    
    # Store event for chronological sorting
    event_count++
    events[event_count] = timestamp_ns "|" src_name "|" dst_name "|" direction "|" timestamp_human
}

END {
    if (event_count == 0) {
        print "note over User: No events found for signature " signature
        print "@enduml"
        exit 0
    }
    
    # Declare participants in order of appearance
    for (i = 1; i <= participant_count; i++) {
        name = participant_order[i]
        # Determine participant type based on name
        if (index(name, "audio-source") > 0) {
            print "participant \"" name "\" as " make_alias(name) " #lightblue"
        } else if (index(name, "audio-relay") > 0) {
            print "participant \"" name "\" as " make_alias(name) " #lightgreen"
        } else if (index(name, "audio-") > 0) {
            print "participant \"" name "\" as " make_alias(name) " #lightyellow"
        } else if (index(name, ":443") > 0) {
            print "participant \"" name "\" as " make_alias(name) " #pink"
        } else {
            print "participant \"" name "\" as " make_alias(name)
        }
    }
    
    print ""
    
    # Sort events by timestamp
    # Simple bubble sort for awk compatibility
    for (i = 1; i <= event_count; i++) {
        for (j = i + 1; j <= event_count; j++) {
            split(events[i], a, "|")
            split(events[j], b, "|")
            if (a[1] > b[1]) {
                temp = events[i]
                events[i] = events[j]
                events[j] = temp
            }
        }
    }
    
    # Generate sequence arrows
    prev_time = 0
    for (i = 1; i <= event_count; i++) {
        split(events[i], fields, "|")
        timestamp_ns = fields[1]
        src_name = fields[2]
        dst_name = fields[3]
        direction = fields[4]
        timestamp_human = fields[5]
        
        # Calculate time difference from previous event
        if (prev_time > 0) {
            time_diff_ms = (timestamp_ns - prev_time) / 1000000
            if (time_diff_ms > 100) {
                print "note over " make_alias(src_name) ", " make_alias(dst_name) ": " int(time_diff_ms) "ms gap"
            }
        }
        
        # Create arrow with direction annotation
        dir_label = (direction == "1") ? "ingress" : "egress"
        
        # Extract just the time portion from timestamp
        if (match(timestamp_human, /T([0-9:]+\.[0-9]{3})/, arr)) {
            time_str = arr[1]
        } else {
            time_str = timestamp_human
        }
        
        print make_alias(src_name) " -> " make_alias(dst_name) ": sig=" signature " [" dir_label "] @ " time_str
        
        prev_time = timestamp_ns
    }
    
    # Add summary note
    print ""
    print "note over " make_alias(participant_order[1]) ", " make_alias(participant_order[participant_count]) ": Total observations: " event_count
    
    print "@enduml"
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

# Create valid PlantUML alias from name
function make_alias(name) {
    alias = name
    gsub(/[^a-zA-Z0-9_]/, "_", alias)
    return alias
}