rule overlay_marker {
  strings:
    $m = "MALICIOUS_MARKER_12345" wide ascii
  condition:
    $m
}